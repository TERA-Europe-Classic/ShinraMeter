using System;
using Tera.Sniffing;

namespace DamageMeter.Sniffing
{
    public static class SnifferFactory
    {
        public static ITeraSniffer Create()
        {
            // Yurian-specific build: always use the local mirror socket.
            return new TeraSniffer();
        }
    }
}