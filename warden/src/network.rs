// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.
//
// Sandswap warden — guest network setup.
// At boot the warden configures eth0 with the static IPv4 / default route / DNS
// passed via the warden.net_* kernel-cmdline params (the Sandswap bridge+NAT
// backend's guest side; no DHCP). setup_guest_dns writes /etc/resolv.conf.
// setup_guest_network drives rtnetlink via netlink::Handle.

use anyhow::{anyhow, Result};
use nix::mount::{self, MsFlags};
use slog::Logger;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::netlink::{NetInterface, NetIpAddr, NetRoute};
pub(crate) use warden::pure::format_resolv_conf;

const GUEST_DNS_SRC: &str = "/run/sandswap/resolv.conf";
const GUEST_DNS_FILE: &str = "/etc/resolv.conf";


pub fn setup_guest_dns(logger: Logger, dns_list: Vec<String>) -> Result<()> {
    let logger = logger.new(o!("subsystem" => "network"));

    if dns_list.is_empty() {
        info!(logger, "Did not set guest DNS as DNS not received.");
        return Ok(());
    }

    if let Some(parent) = Path::new(GUEST_DNS_SRC).parent() {
        fs::create_dir_all(parent)?;
    }

    match fs::metadata(GUEST_DNS_FILE) {
        Ok(attr) => {
            if attr.is_dir() {
                return Err(anyhow!("{} is a directory", GUEST_DNS_FILE));
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            warn!(
                logger,
                "{} missing in guest rootfs, creating before DNS bind mount", GUEST_DNS_FILE
            );
            if let Some(parent) = Path::new(GUEST_DNS_FILE).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::File::create(GUEST_DNS_FILE)?;
        }
        Err(err) => return Err(anyhow!(err).context(format!("failed to stat {}", GUEST_DNS_FILE))),
    }

    let content = format_resolv_conf(&dns_list);
    fs::write(GUEST_DNS_SRC, &content)?;

    mount::mount(
        Some(GUEST_DNS_SRC),
        GUEST_DNS_FILE,
        Some("bind"),
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|err| anyhow!(err).context("failed to setup guest DNS"))?;

    Ok(())
}

// setup_guest_network configures the guest's eth0 with a static IPv4 address
// and default route from the warden.net_* cmdline params. If cfg.net_ip is None
// the VM stays offline (no net device was attached) — no-op. Errors are
// returned to the caller (main.rs logs them non-fatal, so a VM without
// warden.net_ip still boots).
pub async fn setup_guest_network(logger: Logger, cfg: &crate::config::AgentConfig) -> Result<()> {
    if cfg.net_ip.is_none() && cfg.net_ip6.is_none() {
        info!(
            logger,
            "guest network: no warden.net_ip/net_ip6, staying offline"
        );
        return Ok(());
    }
    let prefix = cfg.net_prefix.unwrap_or(16);
    let mac = cfg.net_mac.clone().unwrap_or_default();
    const IFACE_NAME: &str = "eth0";
    const MTU: u32 = 1500;

    let mut handle = crate::netlink::Handle::new()?;

    // Static addresses: the v4 one from the bridge backend, plus the optional
    // v6 one from the routed-ipv6 backend (both may exist; v6-only is valid).
    let mut ip_addresses: Vec<NetIpAddr> = Vec::new();
    if let Some(ip) = cfg.net_ip {
        ip_addresses.push(NetIpAddr {
            address: ip.to_string(),
            mask: prefix.to_string(),
        });
    }
    if let Some(ip6) = cfg.net_ip6 {
        let prefix6 = cfg.net_prefix6.unwrap_or(64);
        ip_addresses.push(NetIpAddr {
            address: ip6.to_string(),
            mask: prefix6.to_string(),
        });
    }

    // Configure eth0: update_interface finds the link by MAC, deletes any stale
    // addresses, adds the static address(es), renames the link to eth0, sets
    // MTU, and brings it UP.
    let iface = NetInterface {
        name: IFACE_NAME.to_string(),
        hw_addr: mac.clone(),
        mtu: MTU,
        ip_addresses,
        raw_flags: 0,
    };
    handle.update_interface(&iface).await?;
    info!(
        logger,
        "guest network: eth0 configured (v4: {:?}, v6: {:?}) mac {}", cfg.net_ip, cfg.net_ip6, mac
    );

    // Default route via the host bridge gateway. dest must be "0.0.0.0/0" — a
    // bare "0.0.0.0" parses as /32 (a host route). RT_SCOPE_UNIVERSE marks a
    // gateway route.
    let mut routes: Vec<NetRoute> = Vec::new();
    if let Some(gw) = cfg.net_gw {
        routes.push(NetRoute {
            dest: "0.0.0.0/0".to_string(),
            gateway: gw.to_string(),
            source: String::new(),
            device: IFACE_NAME.to_string(),
            scope: libc::RT_SCOPE_UNIVERSE as u32,
            onlink: false,
            ipv6: false,
        });
    }
    if let Some(gw6) = cfg.net_gw6 {
        // IPv6 default route ("::/0"; see netlink add_routes ipv6 handling).
        routes.push(NetRoute {
            dest: "::/0".to_string(),
            gateway: gw6.to_string(),
            source: String::new(),
            device: IFACE_NAME.to_string(),
            scope: libc::RT_SCOPE_UNIVERSE as u32,
            onlink: false,
            ipv6: true,
        });
    }
    if !routes.is_empty() {
        let n = routes.len();
        handle.add_routes(routes).await?;
        info!(
            logger,
            "guest network: default routes configured ({} route(s))", n
        );
    }

    if !cfg.net_dns.is_empty() {
        setup_guest_dns(logger, cfg.net_dns.clone())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_resolv_conf ──────────────────────────────────────────

    #[test]
    fn format_resolv_conf_nameserver_prefix_present() {
        // REGRESSION: the guest-side writer used to emit bare IPs joined by
        // newlines — not a valid resolv.conf (parsers skip non-directive
        // lines). Every server must carry the "nameserver " directive.
        let body = format_resolv_conf(&["8.8.8.8".to_string(), "1.1.1.1".to_string()]);
        assert_eq!(body, "nameserver 8.8.8.8\nnameserver 1.1.1.1\n");
    }

    #[test]
    fn format_resolv_conf_single_and_trims() {
        assert_eq!(
            format_resolv_conf(&[" 8.8.8.8 ".to_string()]),
            "nameserver 8.8.8.8\n"
        );
        assert_eq!(format_resolv_conf(&[]), "\n");
    }
}
