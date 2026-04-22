// Copyright (c) Gothos
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//#define SERVER

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using Data;
using NetworkSniffer;
using Tera;
using Tera.Game;
using Tera.Sniffing;

namespace DamageMeter.Sniffing
{
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
        private readonly IpSniffer _ipSniffer;
        private readonly ConcurrentDictionary<TcpConnection, byte> _isNew = new();
        private readonly Dictionary<string, Server> _serversByIp;
        private TcpConnection _clientToServer;
        private ConnectionDecrypter _decrypter;
        private MessageSplitter _messageSplitter;
        private TcpConnection _serverToClient;
        private bool _connected;
        public int ClientProxyOverhead;
        public int ServerProxyOverhead;

        public override bool Connected
        {
            get => _connected;
            set
            {
                _connected = value;
                _isNew.Keys.ToList().ForEach(x => x.RemoveCallback());
                _isNew.Clear();
            }
        }

        public override bool Enabled
        {
            get => _ipSniffer.Enabled;
            set => _ipSniffer.Enabled = value;
        }

        public TeraSniffer()
        {
            var servers = BasicTeraData.Instance.Servers;
            _serversByIp = servers.GetServersByIp();

            if (BasicTeraData.Instance.WindowData.CaptureMode == CaptureMode.Npcap)
            {
                var source = _serversByIp.Keys
                    .Select(s => string.Join(".", s.Split('.').Take(3)) + ".0/24")
                    .Distinct()
                    .ToArray();
                var filter = "tcp and (" + string.Join(" or ", source.Select(x => "(net " + x + ")")) + ")";

                try
                {
                    _ipSniffer = new IpSnifferWinPcap(filter);
                    ((IpSnifferWinPcap)_ipSniffer).Warning += OnWarning;
                }
                catch
                {
                    _ipSniffer = new IpSnifferRawSocketMultipleInterfaces();
                }
            }
            else
            {
                _ipSniffer = new IpSnifferRawSocketMultipleInterfaces();
            }

            var tcpSniffer = new TcpSniffer(_ipSniffer);
            tcpSniffer.NewConnection += HandleNewConnection;
            tcpSniffer.EndConnection += HandleEndConnection;
        }

        public override void CleanupForcefully()
        {
            _clientToServer?.RemoveCallback();
            _serverToClient?.RemoveCallback();
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

        private void HandleMessageReceived(Message message)
        {
            OnMessageReceived(message);
        }

        private void HandleServerToClientDecrypted(byte[] data)
        {
            _messageSplitter.ServerToClient(DateTime.UtcNow, data);
        }

        private void HandleClientToServerDecrypted(byte[] data)
        {
            _messageSplitter.ClientToServer(DateTime.UtcNow, data);
        }

        private void HandleEndConnection(TcpConnection connection)
        {
            if (connection == _clientToServer || connection == _serverToClient)
            {
                _clientToServer?.RemoveCallback();
                _serverToClient?.RemoveCallback();
                Connected = false;
                OnEndConnection();
            }
            else
            {
                connection.RemoveCallback();
            }
            connection.DataReceived -= HandleTcpDataReceived;
        }

        private void HandleNewConnection(TcpConnection connection)
        {
            if (!Connected && (_serversByIp.ContainsKey(connection.Destination.Address.ToString()) || _serversByIp.ContainsKey(connection.Source.Address.ToString())))
            {
                _isNew.TryAdd(connection, 1);
                connection.DataReceived += HandleTcpDataReceived;
            }
        }

        private void HandleTcpDataReceived(TcpConnection connection, byte[] data, int needToSkip)
        {
            if (data.Length == 0)
            {
                if (needToSkip != 0 && (connection == _clientToServer || connection == _serverToClient))
                {
                    _decrypter?.Skip(connection == _clientToServer ? MessageDirection.ClientToServer : MessageDirection.ServerToClient, needToSkip);
                }
                return;
            }

            if (!Connected && _isNew.ContainsKey(connection))
            {
                if (_serversByIp.ContainsKey(connection.Source.Address.ToString()) && data.Take(4).SequenceEqual(new byte[4] { 1, 0, 0, 0 }))
                {
                    _isNew.TryRemove(connection, out _);
                    var server = _serversByIp[connection.Source.Address.ToString()];
                    _serverToClient = connection;
                    _clientToServer = null;
                    ServerProxyOverhead = (int)connection.BytesReceived;
                    _decrypter = new ConnectionDecrypter(server.Region);
                    _decrypter.ClientToServerDecrypted += HandleClientToServerDecrypted;
                    _decrypter.ServerToClientDecrypted += HandleServerToClientDecrypted;
                    _messageSplitter = new MessageSplitter();
                    _messageSplitter.MessageReceived += HandleMessageReceived;
                    _messageSplitter.Resync += OnResync;
                }
                if (_serverToClient != null && _clientToServer == null && _serverToClient.Destination.Equals(connection.Source) && _serverToClient.Source.Equals(connection.Destination))
                {
                    ClientProxyOverhead = (int)connection.BytesReceived;
                    _isNew.TryRemove(connection, out _);
                    _clientToServer = connection;
                    var server = _serversByIp[connection.Destination.Address.ToString()];
                    _isNew.Clear();
                    OnNewConnection(server);
                }
                if (connection.BytesReceived > 65536)
                {
                    _isNew.TryRemove(connection, out _);
                    connection.DataReceived -= HandleTcpDataReceived;
                    connection.RemoveCallback();
                }
            }

            if ((connection != _clientToServer && connection != _serverToClient) || _decrypter == null)
            {
                return;
            }

            if (!_decrypter.Initialized)
            {
                try
                {
                    if (connection == _clientToServer)
                    {
                        _decrypter.ClientToServer(data, needToSkip);
                    }
                    else
                    {
                        _decrypter.ServerToClient(data, needToSkip);
                    }
                    return;
                }
                catch (Exception ex)
                {
                    BasicTeraData.LogError(ex.Message + "\r\n" + ex.StackTrace, true);
                    CleanupForcefully();
                    return;
                }
            }

            if (connection == _clientToServer)
            {
                _decrypter.ClientToServer(data, needToSkip);
            }
            else
            {
                _decrypter.ServerToClient(data, needToSkip);
            }
        }
    }
}
