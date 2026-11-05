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

use anyhow::{anyhow, bail, ensure, Result};
use serde::Deserialize;
use std::env;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time;
use tracing::instrument;

const LOG_LEVEL_OPTION: &str = "warden.log";
const CONFIG_FILE: &str = "warden.config_file";
// Sandswap hardening: per-agent memory cgroup limit (OOM A) and stdout/stderr
// truncation cap. Both read from kernel cmdline as warden.agent_mem_percent /
// warden.max_output_bytes, or env AGENT_MEM_PERCENT / MAX_OUTPUT_BYTES.
const AGENT_MEM_PERCENT_OPTION: &str = "warden.agent_mem_percent";
const MAX_OUTPUT_BYTES_OPTION: &str = "warden.max_output_bytes";
// Per-mount tmpfs size cap for the agent-visible tmpfs mounts (/dev/shm
// always; /tmp in overlay mode). tmpfs pages are unreclaimable, so without a
// size cap a sync exec can walk the guest into the no-killable-victim OOM
// corner (warden/PID 1 is OOM-exempt) — RLIMIT_AS cannot prevent it (tmpfs
// writes don't consume the writer's address space). 0 = auto (MemTotal/4).
const TMPFS_SIZE_MB_OPTION: &str = "warden.tmpfs_size_mb";
// Agent-controllable exec timeouts (sync commands only; background execs are
// bounded by the VM lease, not a per-command timeout). Read from kernel cmdline
// as warden.default_exec_timeout / warden.max_exec_timeout / warden.cgroup_clear_timeout
// (seconds), or env DEFAULT_EXEC_TIMEOUT / MAX_EXEC_TIMEOUT / CGROUP_CLEAR_TIMEOUT.
const DEFAULT_EXEC_TIMEOUT_OPTION: &str = "warden.default_exec_timeout";
const MAX_EXEC_TIMEOUT_OPTION: &str = "warden.max_exec_timeout";
const CGROUP_CLEAR_TIMEOUT_OPTION: &str = "warden.cgroup_clear_timeout";
// Sandswap resilience: the warden single countdown. Read from kernel cmdline
// as warden.warden_countdown_sec (seconds), or env WARDEN_COUNTDOWN_SEC. The
// warden exits the VM (last-resort mount release) when no heartbeat
// (OP_MEM_STATS) arrives within this window while a mount is live.
const WARDEN_COUNTDOWN_OPTION: &str = "warden.warden_countdown_sec";
// File I/O read cap: max bytes a single OP_FILE READ can return. Prevents
// a huge file from blowing up the vsock response frame. Read from kernel
// cmdline as warden.max_file_read_bytes, or env MAX_FILE_READ_BYTES.
const MAX_FILE_READ_BYTES_OPTION: &str = "warden.max_file_read_bytes";
// File I/O write cap: max bytes a single OP_FILE WRITE request body may
// carry (the vsock request frame body). Prevents a malformed frame from
// triggering a multi-GB allocation. Read from kernel cmdline as
// warden.max_body_len, or env MAX_BODY_LEN. Must be >= the gateway/sandlot
// gRPC max_msg_size so a write is never rejected at the vsock layer after
// being accepted over gRPC.
const MAX_BODY_LEN_OPTION: &str = "warden.max_body_len";
// Background exec log cap: bounds a single background exec's log file on the
// RAM-backed initramfs rootfs (/tmp/sandswap-bg). The bg-log watchdog
// (raw_server) truncates past this, keeping the tail. 0 disables the watchdog.
const MAX_BG_LOG_BYTES_OPTION: &str = "warden.max_bg_log_bytes";
// Background exec log TAIL: how many bytes of the merged stdout/stderr the
// relay keeps (and status returns). The relay enforces this continuously, so
// the file never grows past it; max_bg_log_bytes is the aggregate watchdog.
const BG_LOG_TAIL_BYTES_OPTION: &str = "warden.bg_log_tail_bytes";

// Sandswap guest static networking (bridge + kernel NAT backend). When the
// sandlot network provider provisions a VM, it appends these to the kernel
// cmdline; the warden reads them at boot and configures eth0 via netlink. All
// default to None/empty => no guest network setup (offline VM).
const NET_IP_OPTION: &str = "warden.net_ip";
const NET_PREFIX_OPTION: &str = "warden.net_prefix";
const NET_GW_OPTION: &str = "warden.net_gw";
const NET_DNS_OPTION: &str = "warden.net_dns";
const NET_MAC_OPTION: &str = "warden.net_mac";
const NET_IP6_OPTION: &str = "warden.net_ip6";
const NET_PREFIX6_OPTION: &str = "warden.net_prefix6";
const NET_GW6_OPTION: &str = "warden.net_gw6";
const AGENT_MEM_PERCENT_ENV_VAR: &str = "AGENT_MEM_PERCENT";
const TMPFS_SIZE_MB_ENV_VAR: &str = "TMPFS_SIZE_MB";
const MAX_OUTPUT_BYTES_ENV_VAR: &str = "MAX_OUTPUT_BYTES";
const DEFAULT_EXEC_TIMEOUT_ENV_VAR: &str = "DEFAULT_EXEC_TIMEOUT";
const MAX_EXEC_TIMEOUT_ENV_VAR: &str = "MAX_EXEC_TIMEOUT";
const CGROUP_CLEAR_TIMEOUT_ENV_VAR: &str = "CGROUP_CLEAR_TIMEOUT";
const WARDEN_COUNTDOWN_ENV_VAR: &str = "WARDEN_COUNTDOWN_SEC";
const MAX_FILE_READ_BYTES_ENV_VAR: &str = "MAX_FILE_READ_BYTES";
const MAX_BODY_LEN_ENV_VAR: &str = "MAX_BODY_LEN";
const MAX_BG_LOG_BYTES_ENV_VAR: &str = "MAX_BG_LOG_BYTES";
const BG_LOG_TAIL_BYTES_ENV_VAR: &str = "BG_LOG_TAIL_BYTES";
const DEFAULT_AGENT_MEM_PERCENT: u32 = 70;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB

// Defaults shared by Default::default() and the tests. Keep the cross-component
// contract (gateway max exec <= warden max exec < warden countdown) explicit.
const DEFAULT_DEFAULT_EXEC_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_EXEC_TIMEOUT_SECS: u64 = 180;
const DEFAULT_WARDEN_COUNTDOWN_SECS: u64 = 300;
const DEFAULT_MAX_FILE_READ_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_BODY_LEN: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_BG_LOG_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_BG_LOG_TAIL_BYTES: usize = 8 * 1024;

const DEFAULT_LOG_LEVEL: slog::Level = slog::Level::Info;

const LOG_LEVEL_ENV_VAR: &str = "SANDSWAP_WARDEN_LOG_LEVEL";

const ERR_INVALID_LOG_LEVEL: &str = "invalid log level";
const ERR_INVALID_LOG_LEVEL_PARAM: &str = "invalid log level parameter";
const ERR_INVALID_LOG_LEVEL_KEY: &str = "invalid log level key name";

#[derive(Debug)]
pub struct AgentConfig {
    pub log_level: slog::Level,
    // Sandswap hardening:
    // agent_mem_percent: per-agent memory cgroup limit = MemTotal × this / 100.
    //   0 disables the cgroup limit (warden runs without per-agent cap).
    // tmpfs_size_mb: per-mount size cap (MiB) for agent-visible tmpfs mounts
    //   (/dev/shm; /tmp in overlay mode). 0 = auto (MemTotal/4). tmpfs is
    //   unreclaimable memory — the cap turns "fill guest RAM → OOM corner
    //   with no killable victim" into a plain ENOSPC at the writer.
    // max_output_bytes: stdout/stderr are truncated to this many bytes per exec
    //   to keep the warden↔sandlot channel from being blown up by huge output.
    pub agent_mem_percent: u32,
    pub tmpfs_size_mb: u32,
    pub max_output_bytes: usize,
    // default_exec_timeout: the command timeout applied when the caller omits a
    //   timeout (or sends 0). The command is killed via cgroup/kill(-pgid) past
    //   this. 30s covers normal agent tool calls (ls/grep/test) with margin.
    pub default_exec_timeout: time::Duration,
    // max_exec_timeout: upper bound a caller can request; requests above this
    //   are clamped. Bounds runaway commands against the VM lease. Must stay
    //   STRICTLY below warden_countdown below — a max-length exec must finish
    //   (and send its response) before the countdown could fire, so the
    //   countdown only ever trips a cleanup overrun, never a legal long exec.
    pub max_exec_timeout: time::Duration,
    // cgroup_clear_timeout: how long unmount_workspace waits for the per-agent
    //   cgroup to empty after cgroup.kill before proceeding (a D-state process
    //   may linger). Off the /execute E2E path (async detach).
    pub cgroup_clear_timeout: time::Duration,
    // warden_countdown: how long the warden tolerates heartbeat silence while a
    //   sandfs mount is live before exiting the VM (last-resort mount release).
    //   Only OP_MEM_STATS heartbeats reset it; business RPCs (mount/exec/unmount)
    //   deliberately do NOT. The sandlot stops heartbeating at T_tolerance, so a
    //   mount still live at T_tolerance + T_warden triggers reboot(POWER_OFF)
    //   (fallback exit(1)), bounding the mount-clearing window no matter what
    //   sandlot/gateway state is. Must exceed max_exec_timeout (a legit long
    //   exec on the cached connection while probes keep arriving on separate
    //   connections) and cgroup_clear_timeout (an unmount's reap must finish
    //   inside it).
    pub warden_countdown: time::Duration,
    // max_file_read_bytes: hard cap on how many bytes a single OP_FILE READ
    //   can return. Prevents a huge file from blowing up the vsock response
    //   frame. Default 16MB; configurable via kernel cmdline or env var.
    pub max_file_read_bytes: usize,
    // max_body_len: hard cap on a single vsock request frame body (bytes).
    //   Bounds OP_FILE WRITE data (and any request body). Default 16MB;
    //   configurable via kernel cmdline or env var. Kept in lockstep with
    //   max_file_read_bytes so read and write single-op caps are uniform.
    pub max_body_len: usize,
    // max_bg_log_bytes: cap on a single background exec's log file before the
    //   bg-log watchdog truncates it (keeping the tail). Bounds runaway bg
    //   output growth on the RAM-backed initramfs rootfs. 0 disables the
    //   watchdog. Default 64MB — far above normal bg log sizes, far below
    //   what could pressure guest memory.
    pub max_bg_log_bytes: usize,
    // bg_log_tail_bytes: how many bytes of a background exec's merged
    //   stdout/stderr the relay keeps (and status returns). Default 8 KiB;
    //   the relay bounds the file continuously. max_bg_log_bytes remains the
    //   secondary aggregate watchdog.
    pub bg_log_tail_bytes: usize,
    // Sandswap guest static networking (set from warden.net_* cmdline params;
    // None/empty => offline VM, no eth0 setup).
    pub net_ip: Option<Ipv4Addr>,
    pub net_prefix: Option<u8>,
    pub net_gw: Option<Ipv4Addr>,
    pub net_dns: Vec<String>,
    pub net_mac: Option<String>,
    // Routed-IPv6 backend (docs/how-it-works/egress-enabler.md): optional
    // second, static IPv6 configuration alongside the v4 one.
    pub net_ip6: Option<Ipv6Addr>,
    pub net_prefix6: Option<u8>,
    pub net_gw6: Option<Ipv6Addr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigBuilder {
    pub log_level: Option<String>,
}

macro_rules! config_override {
    ($builder:ident, $config:ident, $field:ident) => {
        if let Some(v) = $builder.$field {
            $config.$field = v;
        }
    };

    ($builder:ident, $config:ident, $field:ident, $func: ident) => {
        if let Some(v) = $builder.$field {
            $config.$field = $func(&v)?;
        }
    };
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            log_level: DEFAULT_LOG_LEVEL,
            agent_mem_percent: DEFAULT_AGENT_MEM_PERCENT,
            tmpfs_size_mb: 0, // 0 = kernel default (no size= option)
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            default_exec_timeout: time::Duration::from_secs(DEFAULT_DEFAULT_EXEC_TIMEOUT_SECS),
            max_exec_timeout: time::Duration::from_secs(DEFAULT_MAX_EXEC_TIMEOUT_SECS),
            cgroup_clear_timeout: time::Duration::from_secs(5),
            warden_countdown: time::Duration::from_secs(DEFAULT_WARDEN_COUNTDOWN_SECS),
            max_file_read_bytes: DEFAULT_MAX_FILE_READ_BYTES,
            max_body_len: DEFAULT_MAX_BODY_LEN,
            max_bg_log_bytes: DEFAULT_MAX_BG_LOG_BYTES,
            bg_log_tail_bytes: DEFAULT_BG_LOG_TAIL_BYTES,
            net_ip: None,
            net_prefix: None,
            net_gw: None,
            net_dns: Vec::new(),
            net_mac: None,
            net_ip6: None,
            net_prefix6: None,
            net_gw6: None,
        }
    }
}

impl FromStr for AgentConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let agent_config_builder: AgentConfigBuilder =
            toml::from_str(s).map_err(anyhow::Error::new)?;
        let mut agent_config: AgentConfig = Default::default();

        // Overwrite default values with the configuration files ones.
        config_override!(
            agent_config_builder,
            agent_config,
            log_level,
            parse_log_level
        );

        Ok(agent_config)
    }
}

// parse_cmdline_param parse commandline parameters.
macro_rules! parse_cmdline_param {
    // commandline flags, without func to parse the option values
    ($param:ident, $key:ident, $field:expr) => {
        if $param.eq(&$key) {
            $field = true;
            continue;
        }
    };
    // commandline options, with func to parse the option values
    ($param:ident, $key:ident, $field:expr, $func:ident) => {
        if $param.starts_with(format!("{}=", $key).as_str()) {
            let val = $func($param)?;
            $field = val;
            continue;
        }
    };
    // commandline options, with func to parse the option values, and match func
    // to valid the values
    ($param:ident, $key:ident, $field:expr, $func:ident, $guard:expr) => {
        if $param.starts_with(format!("{}=", $key).as_str()) {
            let val = $func($param)?;
            if $guard(val) {
                $field = val;
            }
            continue;
        }
    };
}

impl AgentConfig {
    #[instrument]
    pub fn from_cmdline(file: &str, args: Vec<String>) -> Result<AgentConfig> {
        // The config file supplies the BASE values; every command-line
        // parameter below still applies on top of it. An early return here
        // used to silently discard the hardening and network parameters (the
        // VM booted offline) whenever a config file was named.
        let mut config_file: Option<String> = None;
        if let Some(config_position) = args.iter().position(|a| a == "--config" || a == "-c") {
            if let Some(path) = args.get(config_position + 1) {
                config_file = Some(path.clone());
            } else {
                // bail, never panic: this runs inside PID 1, where a panic
                // unwinds past every POWER_OFF path and leaves a hung VM
                // (kernel panic on init death) instead of a power-off.
                bail!("The config argument wasn't formed properly: {:?}", args);
            }
        }

        let cmdline = fs::read_to_string(file)?;
        // `warden.config_file=` on the kernel command line is the other way
        // to name the file; it loses to an explicit --config argument.
        if config_file.is_none() {
            for param in cmdline.split_ascii_whitespace() {
                if param.starts_with(format!("{}=", CONFIG_FILE).as_str()) {
                    config_file = Some(get_string_value(param)?);
                    break;
                }
            }
        }

        let mut config: AgentConfig = match config_file.as_deref() {
            Some(path) => AgentConfig::from_config_file(path)?,
            None => Default::default(),
        };

        let params: Vec<&str> = cmdline.split_ascii_whitespace().collect();
        for param in params.iter() {
            // The file was already applied as the base; command-line
            // parameters override it one by one (same order as before).
            if param.starts_with(format!("{}=", CONFIG_FILE).as_str()) {
                continue;
            }

            // parse cmdline options
            parse_cmdline_param!(param, LOG_LEVEL_OPTION, config.log_level, get_log_level);

            // Sandswap hardening: warden.agent_mem_percent=<u32>
            // (0 disables the per-exec memory cgroup cap).
            if let Some(rest) = param.strip_prefix(&format!("{}=", AGENT_MEM_PERCENT_OPTION)) {
                config.agent_mem_percent = rest.parse::<u32>().unwrap_or(DEFAULT_AGENT_MEM_PERCENT);
                continue;
            }
            // Sandswap hardening: warden.tmpfs_size_mb=<u32> (0 = kernel default).
            if let Some(rest) = param.strip_prefix(&format!("{}=", TMPFS_SIZE_MB_OPTION)) {
                config.tmpfs_size_mb = rest.parse::<u32>().unwrap_or(0);
                continue;
            }
            // Sandswap hardening: warden.max_output_bytes=<usize>. 0 falls
            // back to the default: a 0 cap would silently truncate EVERY
            // exec's stdout/stderr to nothing (drain_pipe caps at 0 bytes),
            // indistinguishable from a command that printed nothing.
            if let Some(rest) = param.strip_prefix(&format!("{}=", MAX_OUTPUT_BYTES_OPTION)) {
                if let Ok(b) = rest.parse::<usize>() {
                    if b > 0 {
                        config.max_output_bytes = b;
                    }
                }
                continue;
            }

            // Sandswap agent-controllable exec timeouts (seconds). default is
            // used when the caller omits timeout; max is the safety floor that
            // clamps caller values (the gateway also clamps, but the warden is
            // the independent final authority). cgroup_clear_timeout bounds the
            // agent-switch reap. All sync-exec only.
            if let Some(rest) = param.strip_prefix(&format!("{}=", DEFAULT_EXEC_TIMEOUT_OPTION)) {
                if let Ok(s) = rest.parse::<u64>() {
                    if s > 0 {
                        config.default_exec_timeout = time::Duration::from_secs(s);
                    }
                }
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", MAX_EXEC_TIMEOUT_OPTION)) {
                if let Ok(s) = rest.parse::<u64>() {
                    if s > 0 {
                        config.max_exec_timeout = time::Duration::from_secs(s);
                    }
                }
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", CGROUP_CLEAR_TIMEOUT_OPTION)) {
                if let Ok(s) = rest.parse::<u64>() {
                    if s > 0 {
                        config.cgroup_clear_timeout = time::Duration::from_secs(s);
                    }
                }
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", WARDEN_COUNTDOWN_OPTION)) {
                if let Ok(s) = rest.parse::<u64>() {
                    if s > 0 {
                        config.warden_countdown = time::Duration::from_secs(s);
                    }
                }
                continue;
            }
            // File I/O read cap.
            if let Some(rest) = param.strip_prefix(&format!("{}=", MAX_FILE_READ_BYTES_OPTION)) {
                if let Ok(b) = rest.parse::<usize>() {
                    if b > 0 {
                        config.max_file_read_bytes = b;
                    }
                }
                continue;
            }
            // File I/O write cap (vsock request body limit).
            if let Some(rest) = param.strip_prefix(&format!("{}=", MAX_BODY_LEN_OPTION)) {
                if let Ok(b) = rest.parse::<usize>() {
                    if b > 0 {
                        config.max_body_len = b;
                    }
                }
                continue;
            }
            // Background exec log cap (0 explicitly allowed: disables the
            // bg-log watchdog).
            if let Some(rest) = param.strip_prefix(&format!("{}=", MAX_BG_LOG_BYTES_OPTION)) {
                if let Ok(b) = rest.parse::<usize>() {
                    config.max_bg_log_bytes = b;
                }
                continue;
            }
            // Background exec log tail (0 = keep the default).
            if let Some(rest) = param.strip_prefix(&format!("{}=", BG_LOG_TAIL_BYTES_OPTION)) {
                if let Ok(b) = rest.parse::<usize>() {
                    if b > 0 {
                        config.bg_log_tail_bytes = b;
                    }
                }
                continue;
            }

            // Sandswap guest static networking (bridge+NAT backend). The sandlot
            // network provider appends these to the kernel cmdline when it
            // provisions a VM; we read them here and hand them to network setup
            // at boot. Missing/empty => offline VM.
            if let Some(rest) = param.strip_prefix(&format!("{}=", NET_IP_OPTION)) {
                if let Ok(ip) = rest.parse::<Ipv4Addr>() {
                    config.net_ip = Some(ip);
                }
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", NET_PREFIX_OPTION)) {
                if let Ok(p) = rest.parse::<u8>() {
                    config.net_prefix = Some(p);
                }
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", NET_GW_OPTION)) {
                if let Ok(gw) = rest.parse::<Ipv4Addr>() {
                    config.net_gw = Some(gw);
                }
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", NET_DNS_OPTION)) {
                // Comma-separated nameservers.
                config.net_dns = rest
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", NET_MAC_OPTION)) {
                config.net_mac = Some(rest.to_string());
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", NET_IP6_OPTION)) {
                if let Ok(ip) = rest.parse::<Ipv6Addr>() {
                    config.net_ip6 = Some(ip);
                }
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", NET_PREFIX6_OPTION)) {
                if let Ok(p) = rest.parse::<u8>() {
                    config.net_prefix6 = Some(p);
                }
                continue;
            }
            if let Some(rest) = param.strip_prefix(&format!("{}=", NET_GW6_OPTION)) {
                if let Ok(gw) = rest.parse::<Ipv6Addr>() {
                    config.net_gw6 = Some(gw);
                }
                continue;
            }
        }

        if let Ok(addr) = env::var(LOG_LEVEL_ENV_VAR) {
            if let Ok(level) = parse_log_level(&addr) {
                config.log_level = level;
            }
        }

        // Sandswap hardening env overrides.
        if let Ok(value) = env::var(AGENT_MEM_PERCENT_ENV_VAR) {
            if let Ok(p) = value.parse::<u32>() {
                config.agent_mem_percent = p;
            }
        }
        if let Ok(value) = env::var(TMPFS_SIZE_MB_ENV_VAR) {
            if let Ok(m) = value.parse::<u32>() {
                config.tmpfs_size_mb = m;
            }
        }
        if let Ok(value) = env::var(MAX_OUTPUT_BYTES_ENV_VAR) {
            if let Ok(b) = value.parse::<usize>() {
                if b > 0 {
                    config.max_output_bytes = b;
                }
            }
        }
        // Exec timeout env overrides (seconds). Sync-exec only.
        if let Ok(value) = env::var(DEFAULT_EXEC_TIMEOUT_ENV_VAR) {
            if let Ok(s) = value.parse::<u64>() {
                if s > 0 {
                    config.default_exec_timeout = time::Duration::from_secs(s);
                }
            }
        }
        if let Ok(value) = env::var(MAX_EXEC_TIMEOUT_ENV_VAR) {
            if let Ok(s) = value.parse::<u64>() {
                if s > 0 {
                    config.max_exec_timeout = time::Duration::from_secs(s);
                }
            }
        }
        if let Ok(value) = env::var(CGROUP_CLEAR_TIMEOUT_ENV_VAR) {
            if let Ok(s) = value.parse::<u64>() {
                if s > 0 {
                    config.cgroup_clear_timeout = time::Duration::from_secs(s);
                }
            }
        }
        if let Ok(value) = env::var(WARDEN_COUNTDOWN_ENV_VAR) {
            if let Ok(s) = value.parse::<u64>() {
                if s > 0 {
                    config.warden_countdown = time::Duration::from_secs(s);
                }
            }
        }
        // File I/O read cap env override.
        if let Ok(value) = env::var(MAX_FILE_READ_BYTES_ENV_VAR) {
            if let Ok(b) = value.parse::<usize>() {
                if b > 0 {
                    config.max_file_read_bytes = b;
                }
            }
        }
        // File I/O write cap env override (vsock request body limit).
        if let Ok(value) = env::var(MAX_BODY_LEN_ENV_VAR) {
            if let Ok(b) = value.parse::<usize>() {
                if b > 0 {
                    config.max_body_len = b;
                }
            }
        }
        // Background exec log cap env override (0 = disable the watchdog).
        if let Ok(value) = env::var(MAX_BG_LOG_BYTES_ENV_VAR) {
            if let Ok(b) = value.parse::<usize>() {
                config.max_bg_log_bytes = b;
            }
        }
        // Background exec log tail env override (0 = keep the default).
        if let Ok(value) = env::var(BG_LOG_TAIL_BYTES_ENV_VAR) {
            if let Ok(b) = value.parse::<usize>() {
                if b > 0 {
                    config.bg_log_tail_bytes = b;
                }
            }
        }
        // Hard ceilings: the gateway derives its mount-release proof from the
        // countdown IT configured, while the warden raises the effective
        // countdown to the longest legal exec. An unbounded value would let a
        // config (or a mistaken deploy) stretch that proof silently. Values
        // beyond the supported maximum are a configuration error, not a clamp.
        const MAX_EXEC_TIMEOUT_CEILING_SECS: u64 = 3600;
        const COUNTDOWN_CEILING_SECS: u64 = MAX_EXEC_TIMEOUT_CEILING_SECS + 600;
        if config.max_exec_timeout > time::Duration::from_secs(MAX_EXEC_TIMEOUT_CEILING_SECS) {
            return Err(anyhow!(
                "warden.max_exec_timeout {}s exceeds the supported maximum {}s",
                config.max_exec_timeout.as_secs(),
                MAX_EXEC_TIMEOUT_CEILING_SECS
            ));
        }
        if config.warden_countdown > time::Duration::from_secs(COUNTDOWN_CEILING_SECS) {
            return Err(anyhow!(
                "warden.warden_countdown {}s exceeds the supported maximum {}s",
                config.warden_countdown.as_secs(),
                COUNTDOWN_CEILING_SECS
            ));
        }
        // Sanity: default must not exceed max (else parse_timeout_ms clamps
        // every default to max, surprising the operator).
        if config.default_exec_timeout > config.max_exec_timeout {
            config.default_exec_timeout = config.max_exec_timeout;
        }
        // Sanity: the warden countdown must outlive the longest legal exec (a
        // max-length exec on the cached connection could otherwise trip it if
        // the probe connection is also blocked) and the cgroup-clear wait (an
        // unmount's reap must finish inside it). Clamp up to the tighter bound.
        if config.warden_countdown < config.max_exec_timeout {
            config.warden_countdown = config.max_exec_timeout;
        }
        if config.warden_countdown < config.cgroup_clear_timeout {
            config.warden_countdown = config.cgroup_clear_timeout;
        }

        Ok(config)
    }

    #[instrument]
    pub fn from_config_file(file: &str) -> Result<AgentConfig> {
        let config = fs::read_to_string(file)?;
        AgentConfig::from_str(&config)
    }
}

/// Parse a log level string (trace/debug/info/warn/error/critical/fatal/panic)
/// into the equivalent slog::Level.
#[instrument]
fn parse_log_level(level: &str) -> Result<slog::Level> {
    let level = match level {
        "fatal" | "panic" => slog::Level::Critical,
        "critical" => slog::Level::Critical,
        "error" => slog::Level::Error,
        "warn" | "warning" => slog::Level::Warning,
        "info" => slog::Level::Info,
        "debug" => slog::Level::Debug,
        "trace" => slog::Level::Trace,
        _ => bail!(ERR_INVALID_LOG_LEVEL),
    };

    Ok(level)
}

#[instrument]
fn get_log_level(param: &str) -> Result<slog::Level> {
    let fields: Vec<&str> = param.split('=').collect();
    ensure!(fields.len() == 2, ERR_INVALID_LOG_LEVEL_PARAM);
    ensure!(fields[0] == LOG_LEVEL_OPTION, ERR_INVALID_LOG_LEVEL_KEY);

    parse_log_level(fields[1])
}

// Return the value from a "name=value" string.
#[instrument]
fn get_string_value(param: &str) -> Result<String> {
    let fields: Vec<&str> = param.split('=').collect();
    ensure!(fields.len() >= 2, "expected name=value");

    // We need name (but the value can be blank)
    ensure!(!fields[0].is_empty(), "name=value parameter missing name");

    let value = fields[1..].join("=");
    ensure!(!value.is_empty(), "name=value parameter missing value");

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ── parse_log_level ─────────────────────────────────────────────

    #[test]
    fn parse_log_level_all_valid() {
        assert_eq!(parse_log_level("trace").unwrap(), slog::Level::Trace);
        assert_eq!(parse_log_level("debug").unwrap(), slog::Level::Debug);
        assert_eq!(parse_log_level("info").unwrap(), slog::Level::Info);
        assert_eq!(parse_log_level("warn").unwrap(), slog::Level::Warning);
        assert_eq!(parse_log_level("warning").unwrap(), slog::Level::Warning);
        assert_eq!(parse_log_level("error").unwrap(), slog::Level::Error);
        assert_eq!(parse_log_level("critical").unwrap(), slog::Level::Critical);
        assert_eq!(parse_log_level("fatal").unwrap(), slog::Level::Critical);
        assert_eq!(parse_log_level("panic").unwrap(), slog::Level::Critical);
    }

    #[test]
    fn parse_log_level_invalid() {
        assert!(parse_log_level("verbose").is_err());
        assert!(parse_log_level("").is_err());
        assert!(parse_log_level("INFO").is_err()); // case-sensitive
    }

    // ── get_log_level ───────────────────────────────────────────────

    #[test]
    fn get_log_level_valid() {
        assert_eq!(get_log_level("warden.log=info").unwrap(), slog::Level::Info);
        assert_eq!(
            get_log_level("warden.log=debug").unwrap(),
            slog::Level::Debug
        );
    }

    #[test]
    fn get_log_level_wrong_key() {
        assert!(get_log_level("other.log=info").is_err());
    }

    #[test]
    fn get_log_level_invalid_level() {
        assert!(get_log_level("warden.log=verbose").is_err());
    }

    // ── get_string_value ────────────────────────────────────────────

    #[test]
    fn get_string_value_simple() {
        assert_eq!(get_string_value("key=value").unwrap(), "value");
    }

    #[test]
    fn get_string_value_value_contains_equals() {
        // "key=a=b" → value is "a=b"
        assert_eq!(get_string_value("key=a=b").unwrap(), "a=b");
    }

    #[test]
    fn get_string_value_missing_value() {
        assert!(get_string_value("key=").is_err());
    }

    #[test]
    fn get_string_value_no_equals() {
        assert!(get_string_value("justakey").is_err());
    }

    // ── AgentConfig::default ────────────────────────────────────────

    #[test]
    fn default_config_values() {
        let c = AgentConfig::default();
        assert_eq!(c.log_level, DEFAULT_LOG_LEVEL);
        assert_eq!(c.agent_mem_percent, DEFAULT_AGENT_MEM_PERCENT);
        assert_eq!(c.max_output_bytes, DEFAULT_MAX_OUTPUT_BYTES);
        assert_eq!(c.default_exec_timeout, time::Duration::from_secs(30));
        assert_eq!(c.max_exec_timeout, time::Duration::from_secs(180));
        assert_eq!(c.cgroup_clear_timeout, time::Duration::from_secs(5));
        assert_eq!(c.warden_countdown, time::Duration::from_secs(300));
        assert_eq!(c.max_file_read_bytes, 16 * 1024 * 1024);
        assert_eq!(c.max_body_len, 16 * 1024 * 1024);
        assert_eq!(c.bg_log_tail_bytes, 8 * 1024);
        assert!(c.net_ip.is_none());
        assert!(c.net_prefix.is_none());
        assert!(c.net_gw.is_none());
        assert!(c.net_dns.is_empty());
        assert!(c.net_mac.is_none());
    }

    // ── AgentConfig::from_str (TOML) ────────────────────────────────

    #[test]
    fn from_str_empty_toml() {
        let c = AgentConfig::from_str("").unwrap();
        // Defaults preserved when TOML is empty.
        assert_eq!(c.log_level, DEFAULT_LOG_LEVEL);
    }

    #[test]
    fn from_str_override_log_level() {
        let c = AgentConfig::from_str("log_level = \"debug\"").unwrap();
        assert_eq!(c.log_level, slog::Level::Debug);
    }

    #[test]
    fn from_str_invalid_toml() {
        assert!(AgentConfig::from_str("not valid toml [[[").is_err());
    }

    // ── AgentConfig::from_cmdline ───────────────────────────────────

    #[test]
    fn from_cmdline_network_params() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(
            f,
            "warden.net_ip=10.0.0.2 warden.net_prefix=24 warden.net_gw=10.0.0.1 \
             warden.net_dns=8.8.8.8,1.1.1.1 warden.net_mac=52:54:00:12:34:56"
        )
        .unwrap();
        drop(f);

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        assert_eq!(c.net_ip, Some("10.0.0.2".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(c.net_prefix, Some(24));
        assert_eq!(c.net_gw, Some("10.0.0.1".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(c.net_dns, vec!["8.8.8.8", "1.1.1.1"]);
        assert_eq!(c.net_mac, Some("52:54:00:12:34:56".to_string()));
    }

    #[test]
    fn from_cmdline_network_params_ipv6() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(
            f,
            "warden.net_ip6=fd00:5341:4e44:1:2::42 warden.net_prefix6=64 warden.net_gw6=fd00:5341:4e44:1::1"
        )
        .unwrap();
        drop(f);

        // Routed-ipv6 backend: v6-only provisioning (no warden.net_ip) must
        // parse and leave net_ip offline.
        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        assert!(c.net_ip.is_none());
        assert_eq!(
            c.net_ip6,
            Some("fd00:5341:4e44:1:2::42".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(c.net_prefix6, Some(64));
        assert_eq!(
            c.net_gw6,
            Some("fd00:5341:4e44:1::1".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn from_cmdline_timeout_params() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(
            f,
            "warden.default_exec_timeout=10 warden.max_exec_timeout=120 \
             warden.cgroup_clear_timeout=3"
        )
        .unwrap();
        drop(f);

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        assert_eq!(c.default_exec_timeout, time::Duration::from_secs(10));
        assert_eq!(c.max_exec_timeout, time::Duration::from_secs(120));
        assert_eq!(c.cgroup_clear_timeout, time::Duration::from_secs(3));
    }

    #[test]
    fn from_cmdline_default_clamped_to_max() {
        // If default > max, default is clamped to max.
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(
            f,
            "warden.default_exec_timeout=600 warden.max_exec_timeout=60"
        )
        .unwrap();
        drop(f);

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        assert_eq!(c.default_exec_timeout, time::Duration::from_secs(60));
    }

    #[test]
    fn from_cmdline_hardening_params() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(
            f,
            "warden.agent_mem_percent=80 warden.tmpfs_size_mb=48 warden.max_output_bytes=2097152 \
             warden.max_file_read_bytes=33554432 warden.max_body_len=8388608 \
             warden.bg_log_tail_bytes=16384"
        )
        .unwrap();
        drop(f);

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        assert_eq!(c.agent_mem_percent, 80);
        assert_eq!(c.tmpfs_size_mb, 48);
        assert_eq!(c.max_output_bytes, 2097152);
        assert_eq!(c.max_file_read_bytes, 33554432);
        assert_eq!(c.max_body_len, 8388608);
        assert_eq!(c.bg_log_tail_bytes, 16384);
    }

    #[test]
    fn from_cmdline_zero_output_cap_falls_back_to_default() {
        // max_output_bytes=0 would truncate EVERY exec's stdout/stderr to
        // nothing — indistinguishable from a command that printed nothing —
        // so 0 falls back to the default (mirrors max_file_read_bytes /
        // max_body_len, which have always had the > 0 guard).
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline_zero_out")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(f, "warden.max_output_bytes=0").unwrap();
        drop(f);

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        assert_eq!(c.max_output_bytes, DEFAULT_MAX_OUTPUT_BYTES);
    }

    #[test]
    fn from_cmdline_tmpfs_size_default_is_auto() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline_tmpfs_default")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(f, "warden.agent_mem_percent=70").unwrap();
        drop(f);

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        // 0 = auto (MemTotal/4, resolved at boot by exec_cgroup::init_tmpfs_size).
        assert_eq!(c.tmpfs_size_mb, 0);
    }

    #[test]
    fn from_cmdline_warden_countdown() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(f, "warden.warden_countdown_sec=600").unwrap();
        drop(f);

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        assert_eq!(c.warden_countdown, time::Duration::from_secs(600));
    }

    #[test]
    fn from_cmdline_warden_countdown_clamped_to_max_exec() {
        // A countdown below max_exec_timeout is clamped up: a legit max-length
        // exec must not be able to trip the countdown mid-run.
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(
            f,
            "warden.warden_countdown_sec=30 warden.max_exec_timeout=120"
        )
        .unwrap();
        drop(f);

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        assert_eq!(c.warden_countdown, time::Duration::from_secs(120));
    }

    #[test]
    fn from_cmdline_log_level() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        let mut f = std::fs::File::create(&cmdline_path).unwrap();
        write!(f, "warden.log=debug warden.log_vport=2048").unwrap();
        drop(f);

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        // log_vport is REMOVED: the token must be ignored (unknown param),
        // and the log level still parses.
        assert_eq!(c.log_level, slog::Level::Debug);
    }

    #[test]
    fn from_cmdline_empty_file() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        std::fs::File::create(&cmdline_path).unwrap();

        let c =
            AgentConfig::from_cmdline(cmdline_path.to_str().unwrap(), vec!["warden".to_string()])
                .unwrap();
        // All defaults preserved.
        assert_eq!(c.log_level, DEFAULT_LOG_LEVEL);
        assert_eq!(c.agent_mem_percent, DEFAULT_AGENT_MEM_PERCENT);
    }

    #[test]
    fn from_cmdline_dangling_config_flag_is_err_not_panic() {
        // REGRESSION: "--config" without a value used to panic — inside PID 1
        // that bypasses every POWER_OFF path and hangs the VM (kernel panic
        // on init death). It must surface as a plain Err instead.
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cmdline")
            .tempdir()
            .unwrap();
        let cmdline_path = dir.path().join("cmdline");
        std::fs::File::create(&cmdline_path).unwrap();

        let r = AgentConfig::from_cmdline(
            cmdline_path.to_str().unwrap(),
            vec!["warden".to_string(), "--config".to_string()],
        );
        assert!(
            r.is_err(),
            "dangling --config must be an error, not a panic"
        );
    }

    #[test]
    fn config_file_is_a_base_and_cmdline_overrides() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_cfgmerge")
            .tempdir()
            .unwrap();
        let cfg = dir.path().join("warden.toml");
        std::fs::write(&cfg, "log_level = \"debug\"\n").unwrap();
        let p = dir.path().join("cmdline");
        std::fs::write(
            &p,
            format!(
                "warden.config_file={} warden.net_ip=10.0.0.2 warden.max_exec_timeout=60",
                cfg.display()
            ),
        )
        .unwrap();
        let c = crate::config::AgentConfig::from_cmdline(
            p.to_str().unwrap(),
            vec!["warden".to_string()],
        )
        .unwrap();
        // File value survives, command-line parameters still apply on top (the
        // previous early return silently dropped them, booting the VM offline).
        assert_eq!(c.log_level, slog::Level::Debug);
        assert_eq!(c.net_ip, Some("10.0.0.2".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(c.max_exec_timeout, time::Duration::from_secs(60));
    }

    #[test]
    fn config_file_rejects_unknown_keys() {
        assert!(AgentConfig::from_str("surprise = true").is_err());
    }

    #[test]
    fn exec_timeout_ceiling_is_enforced() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_ceiling")
            .tempdir()
            .unwrap();
        let p = dir.path().join("cmdline");
        std::fs::write(&p, "warden.max_exec_timeout=99999").unwrap();
        assert!(
            crate::config::AgentConfig::from_cmdline(
                p.to_str().unwrap(),
                vec!["warden".to_string()]
            )
            .is_err(),
            "an unbounded max_exec_timeout must be refused, not clamped silently"
        );
    }

    #[test]
    fn from_cmdline_log_level_debug() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_lvl")
            .tempdir()
            .unwrap();
        let p = dir.path().join("cmdline");
        std::fs::write(&p, "quiet clocksource=kvm-clock warden.server_addr=vsock://-1:1024 warden.warden_countdown_sec=300 warden.log=debug console=ttyS0").unwrap();
        let c = crate::config::AgentConfig::from_cmdline(
            p.to_str().unwrap(),
            vec!["warden".to_string()],
        )
        .unwrap();
        assert_eq!(
            c.log_level,
            slog::Level::Debug,
            "cmdline warden.log=debug must set level"
        );
    }
}
