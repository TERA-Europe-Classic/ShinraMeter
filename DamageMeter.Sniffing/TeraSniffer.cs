// Copyright (c) Gothos
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//#define SERVER

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Data;
using Tera;
using Tera.Game;
using Tera.Sniffing;

namespace DamageMeter.Sniffing
{
    public static class TcpClientExtensions
    {
        /// <summary>
        /// Polls the underlying TCP client to determine whether it's connected or not.
        /// </summary>
        public static bool IsConnected(this TcpClient client)
        {
            if (!client.Client.Poll(0, SelectMode.SelectRead))
                return false;
            return client.Client.Receive(new byte[1], SocketFlags.Peek) != 0;
        }
    }

    public class BaseSniffer : ITeraSniffer
    {
        public event Action<Message> MessageReceived;
        public event Action<Server> NewConnection;
        public event Action EndConnection;

        public virtual bool Enabled { get; set; }

        public ConcurrentQueue<Message> Packets { get; private set; } =
            new ConcurrentQueue<Message>();
        public virtual bool Connected { get; set; }

        public void ClearPackets()
        {
            Packets = new ConcurrentQueue<Message>();
        }

        public Queue<Message> GetPacketsLogsAndStop()
        {
            var tmp = PacketsCopyStorage ?? new Queue<Message>();
            EnableMessageStorage = false;
            // Wait for thread to sync, more perf than concurrentQueue
            Thread.Sleep(1);
            return tmp;
        }

        public event Action<string> Warning;

        public virtual void CleanupForcefully()
        {
            Connected = false;
            OnEndConnection();
        }

        private Queue<Message> PacketsCopyStorage;

        private bool _enableMessageStorage;
        public bool EnableMessageStorage
        {
            get => _enableMessageStorage;
            set
            {
                _enableMessageStorage = value;
                if (!_enableMessageStorage)
                {
                    PacketsCopyStorage = null;
                }
            }
        }

        protected virtual void OnNewConnection(Server server)
        {
            PacketsCopyStorage = EnableMessageStorage ? new Queue<Message>() : null;
            NewConnection?.Invoke(server);
        }

        protected virtual void OnMessageReceived(Message message)
        {
            Packets.Enqueue(message);
            PacketsCopyStorage?.Enqueue(message);
        }

        protected virtual void OnEndConnection()
        {
            EndConnection?.Invoke();
        }

        protected virtual void OnWarning(string obj)
        {
            Warning?.Invoke(obj);
        }
    }

    public class TeraSniffer : BaseSniffer
    {
        private MessageSplitter _messageSplitter;

        private bool _enabled;
        private readonly string _socketHost;
        private readonly int _socketPort;
        private CancellationTokenSource _socketCts;
        private Task _socketTask;

        private bool _connected;
        public override bool Connected
        {
            get => _connected;
            set
            {
                if (_connected == value)
                    return;
                _connected = value;
                if (!_connected)
                    OnEndConnection();
            }
        }

        public TeraSniffer()
        {
            _socketHost = "127.0.0.1";
            _socketPort = 7803;
        }

        public TeraSniffer(string socketHost, int socketPort)
        {
            _socketHost = socketHost;
            _socketPort = socketPort;
        }

        public override bool Enabled
        {
            get => _enabled;
            set
            {
                if (_enabled == value)
                    return;
                _enabled = value;

                if (_enabled)
                {
                    if (_socketTask == null || _socketTask.IsCompleted)
                    {
                        _socketCts = new CancellationTokenSource();
                        _socketTask = Task.Run(() =>
                            UnencryptedSocketLoopAsync(_socketCts.Token)
                        );
                    }
                }
                else
                    _socketCts?.Cancel();
            }
        }

        public override void CleanupForcefully()
        {
            try
            {
                _socketCts?.Cancel();
            }
            catch { }
            base.CleanupForcefully();
        }

        private void OnResync(MessageDirection direction, int skipped, int size)
        {
            BasicTeraData.LogError(
                "Resync occured " + direction + ", skipped:" + skipped + ", block size:" + size,
                false,
                true
            );
        }

        // called indirectly from HandleTcpDataReceived, so the current thread already holds the lock
        private void HandleMessageReceived(Message message)
        {
            OnMessageReceived(message);
        }

        // Unencrypted socket mode: connect to a socket and feed already-decrypted frames
        // Mirror frame format: [2b:totalLen][1b:dir][2b:teraLen][opcode][payload]
        // where totalLen = 1 + teraLen (direction byte + full TERA packet)
        private async Task UnencryptedSocketLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                TcpClient client = null;
                try
                {
                    client = new TcpClient();
                    await client.ConnectAsync(_socketHost, _socketPort);
                    Connected = true;
                    var stream = client.GetStream();
                    int packets = 0;

                    var lenBuf = new byte[2];
                    while (!token.IsCancellationRequested)
                    {
                        if (!ReadExact(stream, lenBuf, 2))
                            break;
                        var totalLen = BitConverter.ToUInt16(lenBuf, 0);
                        if (totalLen < 5)
                            continue; // minimal sane frame size: 1 (dir) + 4 (len+opcode minimum)

                        var dirBuf = new byte[1];
                        if (!ReadExact(stream, dirBuf, 1))
                            break;
                        byte direction = dirBuf[0];

                        // Read the inner TERA length field as provided by the mirror
                        var lenField = new byte[2];
                        if (!ReadExact(stream, lenField, 2))
                            break;
                        var teraPacketLen = BitConverter.ToUInt16(lenField, 0);

                        // Sanity check: totalLen should be 1 (dir) + teraPacketLen
                        if (teraPacketLen < 4 || 1 + teraPacketLen != totalLen)
                        {
                            OnWarning($"[Unencrypted] transport/tera length mismatch: totalLen={totalLen}, teraLen={teraPacketLen}");
                        }

                        // Read opcode+payload (teraLen includes its own 2 bytes of length)
                        var restLen = teraPacketLen - 2;
                        var restBuf = new byte[restLen];
                        if (restLen > 0 && !ReadExact(stream, restBuf, restLen))
                            break;

                        // Reconstruct full TERA packet [len(2)][opcode(2)][payload...]
                        var dataBuf = new byte[teraPacketLen];
                        Buffer.BlockCopy(lenField, 0, dataBuf, 0, 2);
                        if (restLen > 0)
                            Buffer.BlockCopy(restBuf, 0, dataBuf, 2, restLen);

                        packets++;

                        // Initialize MessageSplitter and Server on first packet
                        if (packets == 1)
                        {
                            var server = new Tera.Game.Server("Yurian", "EUC", _socketHost);
                            _messageSplitter = new MessageSplitter();
                            _messageSplitter.MessageReceived += HandleMessageReceived;
                            _messageSplitter.Resync += OnResync;
                            OnNewConnection(server);
                        }

                        // Validate direction marker (1=C2S, 2=S2C) and feed to splitter
                        if (direction == 1)
                        {
                            _messageSplitter.ClientToServer(DateTime.UtcNow, dataBuf);
                        }
                        else if (direction == 2)
                        {
                            _messageSplitter.ServerToClient(DateTime.UtcNow, dataBuf);
                        }
                        else
                        {
                            OnWarning($"[Unencrypted] Unknown direction byte={direction}, skipping frame of totalLen={totalLen}");
                            continue;
                        }
                    }
                }
                catch { }
                finally
                {
                    try
                    {
                        client?.Close();
                    }
                    catch { }
                    if (Connected)
                    {
                        Connected = false;
                        OnEndConnection();
                    }
                }
                if (!token.IsCancellationRequested)
                    await Task.Delay(2000, token).ContinueWith(_ => { });
            }
        }

        private static bool ReadExact(NetworkStream stream, byte[] buffer, int length)
        {
            int progress = 0;
            while (progress < length)
            {
                var read = 0;
                try
                {
                    read = stream.Read(buffer, progress, length - progress);
                }
                catch
                {
                    return false;
                }
                if (read <= 0)
                    return false;
                progress += read;
            }
            return true;
        }
    }
}
