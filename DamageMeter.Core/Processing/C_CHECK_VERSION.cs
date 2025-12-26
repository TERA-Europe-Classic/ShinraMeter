using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using DamageMeter.Sniffing;
using Data;
using Lang;
using Tera.Game;

namespace DamageMeter.Processing
{
    internal class C_CHECK_VERSION
    {
        internal C_CHECK_VERSION(Tera.Game.Messages.C_CHECK_VERSION message)
        {
            Debug.WriteLine("VERSION0 = " + message.Versions[0]);
            //            Debug.WriteLine("VERSION1 = " + message.Versions[1]);
            OpcodeDownloader.DownloadIfNotExist(message.Versions[0], Path.Combine(BasicTeraData.Instance.ResourceDirectory, $"data/opcodes/"));

            var expectedPathTxt = Path.Combine(BasicTeraData.Instance.ResourceDirectory, $"data/opcodes/{message.Versions[0]}.txt");
            var expectedPathMap = Path.Combine(BasicTeraData.Instance.ResourceDirectory, $"data/opcodes/protocol.{message.Versions[0]}.map");
            if (!File.Exists(expectedPathTxt) && !File.Exists(expectedPathMap))
            {
                BasicTeraData.LogError("Unknown client version: " + message.Versions[0]);
                MessageBox.Show(LP.Unknown_client_version + message.Versions[0]);
                PacketProcessor.Instance.Exit();
                return;
            }
            var opCodeNamer = new OpCodeNamer(Path.Combine(BasicTeraData.Instance.ResourceDirectory, $"data/opcodes/{message.Versions[0]}.txt"));
            var sysMsgNamer = new OpCodeNamer(Path.Combine(BasicTeraData.Instance.ResourceDirectory, $"data/opcodes/smt_{message.Versions[0]}.txt"));
            /*TeraSniffer.Instance*/
            PacketProcessor.Instance.Sniffer.Connected = true;

            PacketProcessor.Instance.MessageFactory = new MessageFactory(opCodeNamer, PacketProcessor.Instance.Server.Region, message.Versions[0], false, sysMsgNamer);
        }
    }
}