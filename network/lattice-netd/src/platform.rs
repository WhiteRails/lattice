use lattice_net_core::profile::{EnrollmentBundle, GatewayConfig};

#[cfg(target_os = "linux")]
mod implementation {
    use std::ffi::OsString;
    use std::net::IpAddr;
    use std::process::Command;

    use super::*;
    use lattice_net_core::policy::TunnelMode;

    pub struct PlatformNetworkGuard {
        cleanup: Vec<(String, Vec<OsString>)>,
    }

    impl PlatformNetworkGuard {
        pub fn configure(tun_name: &str, gateway: &GatewayConfig, profile: &EnrollmentBundle) -> Result<Self, Box<dyn std::error::Error>> {
            let mut guard = Self { cleanup: Vec::new() };
            match profile.payload.policy.mode {
                TunnelMode::Split => {
                    for route in &profile.payload.routes {
                        let family = if route.addr().is_ipv4() { vec![] } else { vec![OsString::from("-6")] };
                        let mut args = family;
                        args.extend(["route".into(), "add".into(), route.to_string().into(), "dev".into(), tun_name.into()]);
                        guard.run_with_cleanup("ip", args, {
                            let mut cleanup = if route.addr().is_ipv4() { vec![] } else { vec![OsString::from("-6")] };
                            cleanup.extend(["route".into(), "del".into(), route.to_string().into(), "dev".into(), tun_name.into()]);
                            cleanup
                        })?;
                    }
                }
                TunnelMode::Full => guard.configure_full_tunnel(tun_name, gateway, profile)?,
            }
            Ok(guard)
        }

        fn configure_full_tunnel(&mut self, tun_name: &str, gateway: &GatewayConfig, profile: &EnrollmentBundle) -> Result<(), Box<dyn std::error::Error>> {
            let profile_bytes = profile.payload.profile_id.as_bytes();
            let table = 20_000u32 + u16::from_be_bytes([profile_bytes[0], profile_bytes[1]]) as u32 % 10_000;
            let table_string = table.to_string();
            let gateway_ip = gateway.address.ip();
            let family_flag: Vec<OsString> = if gateway_ip.is_ipv4() { vec![] } else { vec!["-6".into()] };
            let gateway_prefix = match gateway_ip { IpAddr::V4(ip) => format!("{ip}/32"), IpAddr::V6(ip) => format!("{ip}/128") };

            let mut bypass = family_flag.clone();
            bypass.extend(["rule".into(), "add".into(), "priority".into(), "99".into(), "to".into(), gateway_prefix.clone().into(), "table".into(), "main".into()]);
            let mut bypass_cleanup = family_flag.clone();
            bypass_cleanup.extend(["rule".into(), "del".into(), "priority".into(), "99".into(), "to".into(), gateway_prefix.into(), "table".into(), "main".into()]);
            self.run_with_cleanup("ip", bypass, bypass_cleanup)?;

            for ipv6 in [false, true] {
                let configured = if ipv6 { profile.payload.interface.ipv6.is_some() } else { profile.payload.interface.ipv4.is_some() };
                if !configured { continue; }
                let prefix: Vec<OsString> = if ipv6 { vec!["-6".into()] } else { vec![] };
                let mut route = prefix.clone();
                route.extend(["route".into(), "add".into(), "default".into(), "dev".into(), tun_name.into(), "table".into(), table_string.clone().into()]);
                let mut route_cleanup = prefix.clone();
                route_cleanup.extend(["route".into(), "del".into(), "default".into(), "dev".into(), tun_name.into(), "table".into(), table_string.clone().into()]);
                self.run_with_cleanup("ip", route, route_cleanup)?;
                let mut rule = prefix.clone();
                rule.extend(["rule".into(), "add".into(), "priority".into(), "100".into(), "table".into(), table_string.clone().into()]);
                let mut rule_cleanup = prefix;
                rule_cleanup.extend(["rule".into(), "del".into(), "priority".into(), "100".into(), "table".into(), table_string.clone().into()]);
                self.run_with_cleanup("ip", rule, rule_cleanup)?;
            }

            let nft_table = format!("lattice_{}", profile.payload.profile_id.simple());
            run("nft", ["add", "table", "inet", &nft_table])?;
            self.cleanup.push(("nft".into(), vec!["delete".into(), "table".into(), "inet".into(), nft_table.clone().into()]));
            run("nft", ["add", "chain", "inet", &nft_table, "output", "{", "type", "filter", "hook", "output", "priority", "-150", ";", "policy", "drop", ";", "}"])?;
            run("nft", ["add", "rule", "inet", &nft_table, "output", "oifname", "lo", "accept"])?;
            run("nft", ["add", "rule", "inet", &nft_table, "output", "oifname", tun_name, "accept"])?;
            let family = if gateway_ip.is_ipv4() { "ip" } else { "ip6" };
            run("nft", ["add", "rule", "inet", &nft_table, "output", family, "daddr", &gateway_ip.to_string(), "udp", "dport", &gateway.address.port().to_string(), "accept"])?;
            Ok(())
        }

        fn run_with_cleanup(&mut self, command: &str, args: Vec<OsString>, cleanup: Vec<OsString>) -> Result<(), Box<dyn std::error::Error>> {
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

    fn run<const N: usize>(command: &str, args: [&str; N]) -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<_> = args.into_iter().map(OsString::from).collect();
        run_os(command, &args)
    }

    fn run_os(command: &str, args: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new(command).args(args).status()?;
        if !status.success() { return Err(format!("{command} failed while applying fail-closed network state").into()); }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod implementation {
    use super::*;

    pub struct PlatformNetworkGuard;

    impl PlatformNetworkGuard {
        pub fn configure(_: &str, _: &GatewayConfig, _: &EnrollmentBundle) -> Result<Self, Box<dyn std::error::Error>> {
            // macOS NetworkExtension and Windows VPN Plug-in own routes and
            // DNS. Direct CLI mode intentionally refuses to claim enforcement.
            Err("direct VPN route enforcement is available only on Linux; use the native platform adapter".into())
        }
    }
}

pub use implementation::PlatformNetworkGuard;
