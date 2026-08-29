using Windows.Networking.Vpn;

namespace Lattice.Network.Windows;

public interface ILatticeLnpEngine
{
    // Validates the signed profile, freshness and platform policy before any
    // OS route or packet callback is accepted.
    void ValidateProfile(VpnChannel channel);
    void Connect(VpnChannel channel);
    void Disconnect();
    void Encapsulate(VpnChannel channel, VpnPacketBufferList source, VpnPacketBufferList destination);
    void Decapsulate(VpnChannel channel, VpnPacketBuffer source, VpnPacketBufferList destination, VpnPacketBufferList control);
    VpnPacketBuffer KeepAlive(VpnChannel channel);
}

public static class LatticeLnpEngineFactory
{
    // The signed MSIX host installs the Rust LNP/1 engine. A package missing
    // that native component never starts a permissive or partial VPN.
    public static Func<ILatticeLnpEngine?>? Create { get; set; }
}

public sealed class VpnPlugin : IVpnPlugIn
{
    private ILatticeLnpEngine? _engine;

    public void Connect(VpnChannel channel)
    {
        try
        {
            _engine = LatticeLnpEngineFactory.Create?.Invoke();
            if (_engine is null)
            {
                channel.TerminateConnection("Lattice LNP/1 native engine is unavailable; failing closed.");
                return;
            }
            _engine.ValidateProfile(channel);
            _engine.Connect(channel);
        }
        catch (Exception error)
        {
            _engine?.Disconnect();
            _engine = null;
            channel.TerminateConnection($"Lattice profile or tunnel setup failed: {error.Message}");
        }
    }

    public void Disconnect(VpnChannel channel)
    {
        _engine?.Disconnect();
        _engine = null;
        channel.Stop();
    }

    public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapsulatedPackets)
    {
        if (_engine is null)
        {
            channel.TerminateConnection("Lattice LNP/1 engine disappeared; failing closed.");
            return;
        }
        _engine.Encapsulate(channel, packets, encapsulatedPackets);
    }

    public void Decapsulate(
        VpnChannel channel,
        VpnPacketBuffer encapBuffer,
        VpnPacketBufferList decapsulatedPackets,
        VpnPacketBufferList controlPacketsToSend)
    {
        if (_engine is null)
        {
            channel.TerminateConnection("Lattice LNP/1 engine disappeared; failing closed.");
            return;
        }
        _engine.Decapsulate(channel, encapBuffer, decapsulatedPackets, controlPacketsToSend);
    }

    public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
    {
        if (_engine is null)
        {
            channel.TerminateConnection("Lattice LNP/1 engine disappeared; failing closed.");
            keepAlivePacket = channel.GetVpnSendPacketBuffer();
            return;
        }
        keepAlivePacket = _engine.KeepAlive(channel);
    }
}
