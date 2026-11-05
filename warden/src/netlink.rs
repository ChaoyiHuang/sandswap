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
// Sandswap warden — guest network configuration via rtnetlink.
// Thin wrapper over the `rtnetlink` crate for the warden's single live network
// task: at boot, configure eth0 (find link by MAC, drop stale addrs, add the
// static IPv4, rename to eth0, set MTU, bring UP) and add the default route.

use anyhow::{anyhow, Context, Result};
use futures::{future, TryStreamExt};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlag, RouteProtocol, RouteScope, RouteType,
};
use nix::errno::Errno;
use rtnetlink::new_connection;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str::FromStr;

macro_rules! sl {
    () => {
        slog_scope::logger().new(o!("subsystem" => "netlink"))
    };
}

/// Search criteria for `find_link`.
enum LinkFilter<'a> {
    Name(&'a str),
    #[allow(dead_code)]
    Address(&'a str),
}

impl fmt::Display for LinkFilter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkFilter::Name(name) => write!(f, "Name: {}", name),
            LinkFilter::Address(addr) => write!(f, "Address: {}", addr),
        }
    }
}

/// Guest interface to configure.
pub struct NetInterface {
    pub name: String,
    pub hw_addr: String,
    pub mtu: u32,
    pub ip_addresses: Vec<NetIpAddr>,
    pub raw_flags: u32,
}

pub struct NetIpAddr {
    pub address: String,
    pub mask: String,
}

/// Route to add.
pub struct NetRoute {
    pub dest: String,
    pub gateway: String,
    pub source: String,
    pub device: String,
    pub scope: u32,
    pub onlink: bool,
    pub ipv6: bool,
}

/// rtnetlink handle for guest network setup.
#[derive(Debug)]
pub struct Handle {
    handle: rtnetlink::Handle,
}

impl Handle {
    pub(crate) fn new() -> Result<Handle> {
        let (conn, handle, _) = new_connection()?;
        tokio::spawn(conn);
        Ok(Handle { handle })
    }

    /// Configure a link: find by MAC, bring down, drop stale addrs, add the new
    /// IPv4, set name/MTU, bring UP.
    pub async fn update_interface(&mut self, iface: &NetInterface) -> Result<()> {
        let link = self.find_link(LinkFilter::Address(&iface.hw_addr)).await?;

        if link.is_up() {
            self.enable_link(link.index(), false).await?;
        }

        let addresses = self.list_addresses(link.index()).await?;
        self.delete_addresses(addresses).await?;

        for ip_address in &iface.ip_addresses {
            let ip = std::net::IpAddr::from_str(&ip_address.address)?;
            let mask = ip_address.mask.parse::<u8>()?;
            self.add_addresses(link.index(), std::iter::once(IpNetwork::new(ip, mask)?))
                .await?;
        }

        let mut request = self.handle.link().set(link.index());
        request.message_mut().header = link.header.clone();

        request
            .mtu(iface.mtu as _)
            .name(iface.name.clone())
            .arp(iface.raw_flags & libc::IFF_NOARP as u32 == 0)
            .up()
            .execute()
            .await?;

        Ok(())
    }

    /// Bring `lo` up.
    pub async fn handle_localhost(&self) -> Result<()> {
        let link = self.find_link(LinkFilter::Name("lo")).await?;
        self.enable_link(link.index(), true).await?;
        Ok(())
    }

    /// Add routes (gateways first). EEXIST is tolerated (route already present).
    pub async fn add_routes<I>(&mut self, list: I) -> Result<()>
    where
        I: IntoIterator<Item = NetRoute>,
    {
        let (a, b): (Vec<NetRoute>, Vec<NetRoute>) =
            list.into_iter().partition(|p| p.gateway.is_empty());
        let list = a.iter().chain(&b);

        for route in list {
            debug!(
                sl!(),
                "add_routes: dest={} gw={} dev={}", route.dest, route.gateway, route.device
            );
            let link = self.find_link(LinkFilter::Name(&route.device)).await?;

            const MAIN_TABLE: u32 = libc::RT_TABLE_MAIN as u32;
            let uni_cast: RouteType = RouteType::from(libc::RTN_UNICAST);
            let boot_prot: RouteProtocol = RouteProtocol::from(libc::RTPROT_BOOT);
            let scope = RouteScope::from(route.scope as u8);

            let mut request = self
                .handle
                .route()
                .add()
                .table_id(MAIN_TABLE)
                .kind(uni_cast)
                .protocol(boot_prot)
                .scope(scope);

            if route.onlink {
                request.message_mut().header.flags.push(RouteFlag::Onlink);
            }

            if route.ipv6 {
                let dest_addr = if !route.dest.is_empty() {
                    Ipv6Network::from_str(&route.dest)?
                } else {
                    Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0)?
                };

                let mut request = request
                    .v6()
                    .destination_prefix(dest_addr.ip(), dest_addr.prefix())
                    .output_interface(link.index());

                if !route.source.is_empty() {
                    let network = Ipv6Network::from_str(&route.source)?;
                    if network.prefix() > 0 {
                        if route.onlink {
                            request = request.pref_source(network.ip());
                        } else {
                            request = request.source_prefix(network.ip(), network.prefix());
                        }
                    } else {
                        request
                            .message_mut()
                            .attributes
                            .push(RouteAttribute::PrefSource(RouteAddress::from(network.ip())));
                    }
                }

                if !route.gateway.is_empty() {
                    let ip = Ipv6Addr::from_str(&route.gateway)?;
                    request = request.gateway(ip);
                }

                if let Err(rtnetlink::Error::NetlinkError(message)) = request.execute().await {
                    if let Some(code) = message.code {
                        if Errno::from_i32(code.get()) != Errno::EEXIST {
                            return Err(anyhow!(
                                "Failed to add IPv6 route (src: {}, dst: {}, gw: {}, err: {})",
                                route.source,
                                route.dest,
                                route.gateway,
                                message
                            ));
                        }
                    }
                }
            } else {
                let dest_addr = if !route.dest.is_empty() {
                    Ipv4Network::from_str(&route.dest)?
                } else {
                    Ipv4Network::new(Ipv4Addr::new(0, 0, 0, 0), 0)?
                };

                let mut request = request
                    .v4()
                    .destination_prefix(dest_addr.ip(), dest_addr.prefix())
                    .output_interface(link.index());

                if !route.source.is_empty() {
                    let network = Ipv4Network::from_str(&route.source)?;
                    if network.prefix() > 0 {
                        if route.onlink {
                            request = request.pref_source(network.ip());
                        } else {
                            request = request.source_prefix(network.ip(), network.prefix());
                        }
                    } else {
                        request
                            .message_mut()
                            .attributes
                            .push(RouteAttribute::PrefSource(RouteAddress::from(network.ip())));
                    }
                }

                if !route.gateway.is_empty() {
                    let ip = Ipv4Addr::from_str(&route.gateway)?;
                    request = request.gateway(ip);
                }

                if let Err(rtnetlink::Error::NetlinkError(message)) = request.execute().await {
                    if let Some(code) = message.code {
                        if Errno::from_i32(code.get()) != Errno::EEXIST {
                            return Err(anyhow!(
                                "Failed to add IPv4 route (src: {}, dst: {}, gw: {}, err: {})",
                                route.source,
                                route.dest,
                                route.gateway,
                                message
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn find_link(&self, filter: LinkFilter<'_>) -> Result<Link> {
        let request = self.handle.link().get();

        let filtered = match filter {
            LinkFilter::Name(name) => request.match_name(name.to_owned()),
            _ => request,
        };

        let mut stream = filtered.execute();

        let next = if let LinkFilter::Address(addr) = filter {
            let mac_addr = parse_mac_address(addr)
                .with_context(|| format!("Failed to parse MAC address: {}", addr))?;

            // Hardware filter might not be supported by netlink, so dump and
            // filter client-side.
            stream
                .try_filter(|f| {
                    let result = f.attributes.iter().any(|n| match n {
                        LinkAttribute::Address(data) => data.eq(&mac_addr),
                        _ => false,
                    });
                    future::ready(result)
                })
                .try_next()
                .await?
        } else {
            stream.try_next().await?
        };

        next.map(|msg| msg.into())
            .ok_or_else(|| anyhow!("Link not found ({})", filter))
    }

    pub(crate) async fn enable_link(&self, link_index: u32, up: bool) -> Result<()> {
        let link_req = self.handle.link().set(link_index);
        let set_req = if up { link_req.up() } else { link_req.down() };
        set_req.execute().await?;
        Ok(())
    }

    async fn list_addresses(&self, link_index: u32) -> Result<Vec<AddressMessage>> {
        let list = self
            .handle
            .address()
            .get()
            .set_link_index_filter(link_index)
            .execute()
            .try_collect()
            .await?;
        Ok(list)
    }

    async fn add_addresses<I>(&mut self, index: u32, list: I) -> Result<()>
    where
        I: IntoIterator<Item = IpNetwork>,
    {
        for net in list.into_iter() {
            self.handle
                .address()
                .add(index, net.ip(), net.prefix())
                .execute()
                .await
                .map_err(|err| anyhow!("Failed to add address {}: {:?}", net.ip(), err))?;
        }
        Ok(())
    }

    async fn delete_addresses<I>(&mut self, list: I) -> Result<()>
    where
        I: IntoIterator<Item = AddressMessage>,
    {
        for addr in list.into_iter() {
            self.handle.address().del(addr).execute().await?;
        }
        Ok(())
    }
}

fn parse_mac_address(addr: &str) -> Result<[u8; 6]> {
    let mut split = addr.splitn(6, ':');
    let mut parse_next = || -> Result<u8> {
        let v = u8::from_str_radix(split.next().ok_or_else(|| anyhow!(nix::Error::EINVAL))?, 16)?;
        Ok(v)
    };
    Ok([
        parse_next()?,
        parse_next()?,
        parse_next()?,
        parse_next()?,
        parse_next()?,
        parse_next()?,
    ])
}

/// Wraps a link message with convenience accessors.
struct Link(netlink_packet_route::link::LinkMessage);

impl Link {
    fn is_up(&self) -> bool {
        let mut flags: u32 = 0;
        for flag in &self.header.flags {
            flags |= u32::from(*flag);
        }
        flags as i32 & libc::IFF_UP > 0
    }

    fn index(&self) -> u32 {
        self.header.index
    }
}

impl From<netlink_packet_route::link::LinkMessage> for Link {
    fn from(msg: netlink_packet_route::link::LinkMessage) -> Self {
        Link(msg)
    }
}

impl Deref for Link {
    type Target = netlink_packet_route::link::LinkMessage;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_mac_address ───────────────────────────────────────────

    #[test]
    fn parse_mac_address_valid() {
        let mac = parse_mac_address("52:54:00:12:34:56").unwrap();
        assert_eq!(mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn parse_mac_address_all_zeros() {
        let mac = parse_mac_address("00:00:00:00:00:00").unwrap();
        assert_eq!(mac, [0u8; 6]);
    }

    #[test]
    fn parse_mac_address_all_ff() {
        let mac = parse_mac_address("ff:ff:ff:ff:ff:ff").unwrap();
        assert_eq!(mac, [0xFF; 6]);
    }

    #[test]
    fn parse_mac_address_too_few_octets() {
        assert!(parse_mac_address("52:54:00:12:34").is_err());
    }

    #[test]
    fn parse_mac_address_invalid_hex() {
        assert!(parse_mac_address("52:54:XX:12:34:56").is_err());
    }

    #[test]
    fn parse_mac_address_empty() {
        assert!(parse_mac_address("").is_err());
    }

    // ── LinkFilter Display ──────────────────────────────────────────

    #[test]
    fn link_filter_display_name() {
        let f = LinkFilter::Name("eth0");
        assert_eq!(format!("{}", f), "Name: eth0");
    }

    #[test]
    fn link_filter_display_address() {
        let f = LinkFilter::Address("52:54:00:12:34:56");
        assert_eq!(format!("{}", f), "Address: 52:54:00:12:34:56");
    }
}
