use lattice_net_core::profile::{EnrollmentBundle, GatewayConfig};

#[cfg(target_os = "linux")]
mod implementation {
    use std::ffi::OsString;
    use std::fs::File;
    use std::hash::{Hash, Hasher};
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::process::{Child, ExitStatus};

    use super::*;
    use lattice_net_core::policy::TunnelMode;

    pub struct PlatformNetworkGuard {
        cleanup: Vec<(String, Vec<OsString>)>,
        full_tunnel_lock: Option<File>,
    }

    impl PlatformNetworkGuard {
        pub fn configure(
            tun_name: &str,
            gateway: &GatewayConfig,
            profile: &EnrollmentBundle,
            manage_dns: bool,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let mut guard = Self {
                cleanup: Vec::new(),
                full_tunnel_lock: None,
            };
            match profile.payload.policy.mode {
                TunnelMode::Split => {
                    for route in &profile.payload.routes {
                        let family = if route.addr().is_ipv4() {
                            vec![]
                        } else {
                            vec![OsString::from("-6")]
                        };
                        let mut args = family;
                        args.extend([
                            "route".into(),
                            "add".into(),
                            route.to_string().into(),
                            "dev".into(),
                            tun_name.into(),
                        ]);
                        guard.run_with_cleanup("ip", args, {
                            let mut cleanup = if route.addr().is_ipv4() {
                                vec![]
                            } else {
                                vec![OsString::from("-6")]
                            };
                            cleanup.extend([
                                "route".into(),
                                "del".into(),
                                route.to_string().into(),
                                "dev".into(),
                                tun_name.into(),
                            ]);
                            cleanup
                        })?;
                    }
                }
                TunnelMode::Full => guard.configure_full_tunnel(tun_name, gateway, profile)?,
            }
            if manage_dns {
                let dns_args = vec![
                    OsString::from("dns"),
                    tun_name.into(),
                    OsString::from("127.0.0.1:5353"),
                ];
                let revert_args = vec![OsString::from("revert"), tun_name.into()];
                guard.run_with_cleanup("resolvectl", dns_args, revert_args)?;
                // Route every private Lattice namespace through the local
                // resolver. Public names continue to use the host's normal
                // DNS links.
                run(
                    "resolvectl",
                    ["domain", tun_name, "~lattice", "~coral", "~reef"],
                )?;
            }
            Ok(guard)
        }

        fn configure_full_tunnel(
            &mut self,
            tun_name: &str,
            gateway: &GatewayConfig,
            profile: &EnrollmentBundle,
        ) -> Result<(), Box<dyn std::error::Error>> {
            use std::os::unix::fs::MetadataExt;
            std::fs::create_dir_all("/run/lattice")?;
            let namespace_inode = std::fs::metadata("/proc/self/ns/net")?.ino();
            let lock_path = format!("/run/lattice/full-tunnel-{namespace_inode}.lock");
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                // This file is only a namespace-scoped advisory lock. Keep
                // any existing bytes intact while taking the lock.
                .truncate(false)
                .open(lock_path)?;
            if unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&lock),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } != 0
            {
                return Err(
                    "another full-tunnel profile already owns this network namespace".into(),
                );
            }
            self.full_tunnel_lock = Some(lock);
            let profile_bytes = profile.payload.profile_id.as_bytes();
            let table = 20_000u32
                + u16::from_be_bytes([profile_bytes[0], profile_bytes[1]]) as u32 % 10_000;
            let table_string = table.to_string();
            let gateway_ip = gateway.address.ip();
            let family_flag: Vec<OsString> = if gateway_ip.is_ipv4() {
                vec![]
            } else {
                vec!["-6".into()]
            };
            let gateway_prefix = match gateway_ip {
                IpAddr::V4(ip) => format!("{ip}/32"),
                IpAddr::V6(ip) => format!("{ip}/128"),
            };

            let mut bypass = family_flag.clone();
            bypass.extend([
                "rule".into(),
                "add".into(),
                "priority".into(),
                "99".into(),
                "to".into(),
                gateway_prefix.clone().into(),
                "table".into(),
                "main".into(),
            ]);
            let mut bypass_cleanup = family_flag.clone();
            bypass_cleanup.extend([
                "rule".into(),
                "del".into(),
                "priority".into(),
                "99".into(),
                "to".into(),
                gateway_prefix.into(),
                "table".into(),
                "main".into(),
            ]);
            self.run_with_cleanup("ip", bypass, bypass_cleanup)?;

            for ipv6 in [false, true] {
                let configured = if ipv6 {
                    profile.payload.interface.ipv6.is_some()
                } else {
                    profile.payload.interface.ipv4.is_some()
                };
                if !configured {
                    continue;
                }
                let prefix: Vec<OsString> = if ipv6 { vec!["-6".into()] } else { vec![] };
                let mut route = prefix.clone();
                route.extend([
                    "route".into(),
                    "add".into(),
                    "default".into(),
                    "dev".into(),
                    tun_name.into(),
                    "table".into(),
                    table_string.clone().into(),
                ]);
                let mut route_cleanup = prefix.clone();
                route_cleanup.extend([
                    "route".into(),
                    "del".into(),
                    "default".into(),
                    "dev".into(),
                    tun_name.into(),
                    "table".into(),
                    table_string.clone().into(),
                ]);
                self.run_with_cleanup("ip", route, route_cleanup)?;
                let mut rule = prefix.clone();
                rule.extend([
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    "100".into(),
                    "table".into(),
                    table_string.clone().into(),
                ]);
                let mut rule_cleanup = prefix;
                rule_cleanup.extend([
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    "100".into(),
                    "table".into(),
                    table_string.clone().into(),
                ]);
                self.run_with_cleanup("ip", rule, rule_cleanup)?;
            }

            let nft_table = format!("lattice_{}", profile.payload.profile_id.simple());
            run("nft", ["add", "table", "inet", &nft_table])?;
            self.cleanup.push((
                "nft".into(),
                vec![
                    "delete".into(),
                    "table".into(),
                    "inet".into(),
                    nft_table.clone().into(),
                ],
            ));
            run(
                "nft",
                [
                    "add", "chain", "inet", &nft_table, "output", "{", "type", "filter", "hook",
                    "output", "priority", "-150", ";", "policy", "drop", ";", "}",
                ],
            )?;
            run(
                "nft",
                [
                    "add", "rule", "inet", &nft_table, "output", "oifname", "lo", "accept",
                ],
            )?;
            run(
                "nft",
                [
                    "add", "rule", "inet", &nft_table, "output", "oifname", tun_name, "accept",
                ],
            )?;
            let family = if gateway_ip.is_ipv4() { "ip" } else { "ip6" };
            run(
                "nft",
                [
                    "add",
                    "rule",
                    "inet",
                    &nft_table,
                    "output",
                    family,
                    "daddr",
                    &gateway_ip.to_string(),
                    "udp",
                    "dport",
                    &gateway.address.port().to_string(),
                    "accept",
                ],
            )?;
            Ok(())
        }

        fn run_with_cleanup(
            &mut self,
            command: &str,
            args: Vec<OsString>,
            cleanup: Vec<OsString>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            run_os(command, &args)?;
            self.cleanup.push((command.to_owned(), cleanup));
            Ok(())
        }
    }

    impl Drop for PlatformNetworkGuard {
        fn drop(&mut self) {
            for (command, args) in self.cleanup.drain(..).rev() {
                let _ = Command::new(command).args(args).status();
            }
        }
    }

    struct IsolatedAgentGuard {
        namespace: String,
        host_table: String,
        resolv_directory: PathBuf,
        children: Vec<Child>,
    }

    impl Drop for IsolatedAgentGuard {
        fn drop(&mut self) {
            for child in &mut self.children {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = Command::new("nft")
                .args(["delete", "table", "inet", &self.host_table])
                .status();
            let _ = Command::new("ip")
                .args(["netns", "delete", &self.namespace])
                .status();
            let _ = std::fs::remove_file(self.resolv_directory.join("resolv.conf"));
            let _ = std::fs::remove_dir(&self.resolv_directory);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_isolated_agent(
        namespace: &str,
        profile: &EnrollmentBundle,
        profile_id: uuid::Uuid,
        control_key: &str,
        state_dir: &Path,
        client_key_ref: &Path,
        lease_path: &Path,
        agent_command: &[OsString],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(
                "per-agent enforcement requires root/CAP_NET_ADMIN; command was not started".into(),
            );
        }
        if std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() != "1" {
            return Err("IPv4 forwarding is disabled; command was not started".into());
        }
        let uid: u32 = std::env::var("SUDO_UID")
            .map_err(|_| "SUDO_UID is required so the agent is never executed as root")?
            .parse()?;
        let gid: u32 = std::env::var("SUDO_GID")
            .map_err(|_| "SUDO_GID is required so the agent is never executed as root")?
            .parse()?;
        if uid == 0 || gid == 0 {
            return Err("agent uid/gid must be unprivileged".into());
        }
        let gateway = profile
            .payload
            .gateways
            .first()
            .ok_or("profile has no gateway")?;
        let IpAddr::V4(gateway_ip) = gateway.address.ip() else {
            return Err(
                "Linux per-agent namespaces currently require an IPv4 QUIC underlay".into(),
            );
        };
        let executable = std::env::current_exe()?.canonicalize()?;
        let resolver = executable.with_file_name("lattice-resolver");
        if !resolver.is_file() {
            return Err("lattice-resolver must be installed beside lattice-netd".into());
        }
        run("setpriv", ["--version"])?;

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        namespace.hash(&mut hasher);
        let suffix = format!("{:08x}", hasher.finish() as u32);
        let host_link = format!("lh{suffix}");
        let peer_link = format!("ln{suffix}");
        let octet = 4 * (u16::from(profile_id.as_bytes()[15]) % 63) + 1;
        let host_address = format!("169.254.250.{octet}/30");
        let peer_address = format!("169.254.250.{}/30", octet + 1);
        let host_gateway = format!("169.254.250.{octet}");
        let host_table = format!("lattice_agent_{suffix}");
        let resolv_directory = PathBuf::from("/etc/netns").join(namespace);
        if resolv_directory.exists() {
            return Err("network namespace DNS state already exists".into());
        }
        run("ip", ["netns", "add", namespace])?;
        let mut guard = IsolatedAgentGuard {
            namespace: namespace.to_owned(),
            host_table: host_table.clone(),
            resolv_directory: resolv_directory.clone(),
            children: Vec::new(),
        };
        run(
            "ip",
            [
                "link", "add", &host_link, "type", "veth", "peer", "name", &peer_link,
            ],
        )?;
        run("ip", ["link", "set", &peer_link, "netns", namespace])?;
        run("ip", ["address", "add", &host_address, "dev", &host_link])?;
        run("ip", ["link", "set", &host_link, "up"])?;
        run_netns(namespace, ["ip", "link", "set", "lo", "up"])?;
        run_netns(
            namespace,
            ["ip", "address", "add", &peer_address, "dev", &peer_link],
        )?;
        run_netns(namespace, ["ip", "link", "set", &peer_link, "up"])?;
        run_netns(
            namespace,
            ["ip", "route", "add", "default", "via", &host_gateway],
        )?;

        run("nft", ["add", "table", "inet", &host_table])?;
        run(
            "nft",
            [
                "add",
                "chain",
                "inet",
                &host_table,
                "forward",
                "{",
                "type",
                "filter",
                "hook",
                "forward",
                "priority",
                "-150",
                ";",
                "policy",
                "drop",
                ";",
                "}",
            ],
        )?;
        run(
            "nft",
            [
                "add",
                "chain",
                "inet",
                &host_table,
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "srcnat",
                ";",
                "}",
            ],
        )?;
        run(
            "nft",
            [
                "add",
                "rule",
                "inet",
                &host_table,
                "forward",
                "iifname",
                &host_link,
                "accept",
            ],
        )?;
        run(
            "nft",
            [
                "add",
                "rule",
                "inet",
                &host_table,
                "forward",
                "oifname",
                &host_link,
                "ct",
                "state",
                "established,related",
                "accept",
            ],
        )?;
        run(
            "nft",
            [
                "add",
                "rule",
                "inet",
                &host_table,
                "postrouting",
                "ip",
                "saddr",
                &peer_address,
                "masquerade",
            ],
        )?;

        std::fs::create_dir(&resolv_directory)?;
        std::fs::write(
            resolv_directory.join("resolv.conf"),
            b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n",
        )?;

        let mut netd = Command::new("ip");
        netd.args(["netns", "exec", namespace])
            .arg(&executable)
            .arg("profile-connect")
            .arg("--profile-id")
            .arg(profile_id.to_string())
            .arg("--trusted-control-key-b64")
            .arg(control_key)
            .arg("--state-dir")
            .arg(state_dir)
            .arg("--client-key-ref")
            .arg(client_key_ref)
            .arg("--tun-name")
            .arg("lp-agent0")
            .arg("--agent-lease")
            .arg(lease_path)
            .arg("--external-dns");
        guard.children.push(netd.spawn()?);

        let mut resolver_child = Command::new("ip");
        resolver_child
            .args(["netns", "exec", namespace])
            .arg(&resolver)
            .arg("--bind")
            .arg("127.0.0.1:53")
            .arg("--profile")
            .arg(state_dir.join(profile_id.to_string()).join("bundle.json"))
            .arg("--trusted-control-key-b64")
            .arg(control_key);
        guard.children.push(resolver_child.spawn()?);

        let mut ready = false;
        for _ in 0..100 {
            if guard
                .children
                .iter_mut()
                .any(|child| child.try_wait().ok().flatten().is_some())
            {
                return Err("VPN or resolver exited before isolation became ready".into());
            }
            if Command::new("ip")
                .args([
                    "netns",
                    "exec",
                    namespace,
                    "ip",
                    "link",
                    "show",
                    "lp-agent0",
                ])
                .status()?
                .success()
            {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !ready {
            return Err("VPN did not become ready; command was not started".into());
        }

        let agent_table = format!("lattice_agent_{suffix}");
        run_netns(namespace, ["nft", "add", "table", "inet", &agent_table])?;
        run_netns(
            namespace,
            [
                "nft",
                "add",
                "chain",
                "inet",
                &agent_table,
                "output",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "-200",
                ";",
                "policy",
                "drop",
                ";",
                "}",
            ],
        )?;
        run_netns(
            namespace,
            [
                "nft",
                "add",
                "rule",
                "inet",
                &agent_table,
                "output",
                "oifname",
                "lo",
                "accept",
            ],
        )?;
        run_netns(
            namespace,
            [
                "nft",
                "add",
                "rule",
                "inet",
                &agent_table,
                "output",
                "oifname",
                "lp-agent0",
                "accept",
            ],
        )?;
        run_netns(
            namespace,
            [
                "nft",
                "add",
                "rule",
                "inet",
                &agent_table,
                "output",
                "ip",
                "daddr",
                &gateway_ip.to_string(),
                "udp",
                "dport",
                &gateway.address.port().to_string(),
                "accept",
            ],
        )?;

        let status: ExitStatus = Command::new("ip")
            .args(["netns", "exec", namespace, "setpriv", "--reuid"])
            .arg(uid.to_string())
            .arg("--regid")
            .arg(gid.to_string())
            .arg("--clear-groups")
            .arg("--no-new-privs")
            .arg("--")
            .args(agent_command)
            .status()?;
        if !status.success() {
            return Err(format!("agent command exited with {status}").into());
        }
        Ok(())
    }

    fn run_netns<const N: usize>(
        namespace: &str,
        args: [&str; N],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("ip")
            .args(["netns", "exec", namespace])
            .args(args)
            .status()?;
        if !status.success() {
            return Err("network namespace isolation command failed".into());
        }
        Ok(())
    }

    fn run<const N: usize>(
        command: &str,
        args: [&str; N],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<_> = args.into_iter().map(OsString::from).collect();
        run_os(command, &args)
    }

    fn run_os(command: &str, args: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new(command).args(args).status()?;
        if !status.success() {
            return Err(
                format!("{command} failed while applying fail-closed network state").into(),
            );
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod implementation {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;

    pub struct PlatformNetworkGuard;

    impl PlatformNetworkGuard {
        pub fn configure(
            _: &str,
            _: &GatewayConfig,
            _: &EnrollmentBundle,
            _: bool,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            // macOS NetworkExtension and Windows VPN Plug-in own routes and
            // DNS. Direct CLI mode intentionally refuses to claim enforcement.
            Err("direct VPN route enforcement is available only on Linux; use the native platform adapter".into())
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_isolated_agent(
        _: &str,
        _: &EnrollmentBundle,
        _: uuid::Uuid,
        _: &str,
        _: &Path,
        _: &Path,
        _: &Path,
        _: &[OsString],
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err("per-agent enforcement is unavailable on this platform; command was not started".into())
    }
}

pub use implementation::{run_isolated_agent, PlatformNetworkGuard};
