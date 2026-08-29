# Windows adapter

`VpnPlugin` is the Windows `IVpnPlugIn` host and the manifest registers both
the VPN provider and the `lttc:` URI scheme. The signed MSIX target must
link the Rust LNP/1 engine and install `LatticeLnpEngineFactory.Create`; absent
that engine, `Connect` calls `TerminateConnection` and no traffic is admitted.

Windows per-app mode must use `VpnChannel.StartWithTrafficFilter` from an
MDM-authorized package. If that policy cannot be installed and verified, the
operator/client must reject per-agent mode. Public packaging remains blocked on
the Microsoft signing identity and store/enterprise distribution credentials.
