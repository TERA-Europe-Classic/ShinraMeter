using System;
using System.Linq;
using Tera.Sniffing;

namespace DamageMeter.Sniffing
{
    public static class SnifferFactory
    {
        public static ITeraSniffer Create()
        {
            var args = Environment.GetCommandLineArgs();
            if (args.Contains("--toolbox")) return new ToolboxSniffer();
            if (args.Contains("--raw")) return new TeraSniffer(); // legacy/raw capture via npcap/raw sockets

            // Unencrypted socket options (preferred)
            // Back-compat: still accept --mirror-host/--mirror-port if provided
            var hostArg = args.FirstOrDefault(a => a.StartsWith("--unencrypted-host="))
                          ?? args.FirstOrDefault(a => a.StartsWith("--mirror-host="));
            var portArg = args.FirstOrDefault(a => a.StartsWith("--unencrypted-port="))
                          ?? args.FirstOrDefault(a => a.StartsWith("--mirror-port="));
            var host = hostArg != null ? hostArg.Split(new[]{'='},2)[1] : "127.0.0.1";
            var port = 7802;
            if (portArg != null)
            {
                var val = portArg.Split(new[]{'='},2)[1];
                if (int.TryParse(val, out var p)) port = p;
            }

            // Default behavior: prefer unencrypted socket mode via TeraSniffer
            // This keeps changes minimal and uses unified MessageSplitter flow
            return new TeraSniffer(unencryptedMode: true, socketHost: host, socketPort: port, isUnencrypted: true);
        }
    }
}