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
using NetworkSniffer;
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

    public class ToolboxSniffer : BaseSniffer
    {
        private readonly bool _failed;
        private bool _enabled;
        private bool _connected;
#if SERVER
        private Thread _listenThread;
#else
        //private Thread _receiveThread;
#endif
        public event Action<int> ReleaseVersionUpdated;

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
#if SERVER
                    _listenThread.Start();
#else
                    Task.Run(ReceiveAsync);
                    //_receiveThread.Start();
#endif
                }
            }
        }

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
#if SERVER
        private readonly TcpListener _dataConnection;
#else
        private TcpClient _dataConnection;
#endif
        public readonly ToolboxControlInterface ControlConnection;

        public ToolboxSniffer()
        {
#if SERVER
            _dataConnection = new TcpListener(IPAddress.Parse("127.0.0.60"), 5300);
#else
            _dataConnection = new TcpClient();
#endif
            ControlConnection = new ToolboxControlInterface("http://127.0.0.61:5300");

            try
            {
#if SERVER
                _dataConnection.Start();
                _listenThread = new Thread(Listen);
#endif
            }
            catch (Exception e)
            {
                //Log.F($"Failed to start Toolbox sniffer: {e}");
                _failed = true;
            }
        }

#if SERVER
        private async void Listen()
        {
            if (_failed)
                return;
            while (Enabled)
            {
                var client = await _dataConnection.AcceptTcpClientAsync();
                var resp = await ControlConnection.GetServerId();
                if (resp != 0)
                {
                    await ControlConnection.AddHooks(MessageFactory.OpcodesList);
                    //PacketAnalyzer.Factory.ReleaseVersion = await ControlConnection.GetReleaseVersion(); //todo: needed?
                    /*NewConnection?.Invoke(Game.DB.ServerDatabase.GetServer(resp)); */OnNewConnection(BasicTeraData.Instance.Servers.GetServer(resp));
                    var rv = await ControlConnection.GetReleaseVersion(); //todo: needed?
                    ReleaseVersionUpdated?.Invoke(rv);
                }
                var stream = client.GetStream();
                while (true)
                {
                    Connected = true;
                    try
                    {
                        var lenBuf = new byte[2];
                        stream.Read(lenBuf, 0, 2);
                        var len = BitConverter.ToUInt16(lenBuf, 0);
                        if (len <= 2)
                        {
                            if (!client.IsConnected())
                            {
                                client.Close();
                                Connected = false;
                                break;
                            }
                            continue;
                        }
                        var length = len - 2;
                        var dataBuf = new byte[length];

                        var progress = 0;
                        while (progress < length)
                        {
                            progress += stream.Read(dataBuf, progress, length - progress);
                        }
                        //MessageReceived?.Invoke(new Message(DateTime.Now, dataBuf));
                        OnMessageReceived(
                            new Message(
                                DateTime.UtcNow,
                                MessageDirection.Unspecified,
                                new ArraySegment<byte>(dataBuf)
                            )
                        );
                    }
                    catch
                    {
                        Connected = false;
                        client.Close();
                        //Log.F($"Disconnected: {e}");
                    }
                }
            }
        }
#else
        private async Task ReceiveAsync()
        {
            if (_failed)
                return;

            while (Enabled)
            {
                var resp = await ControlConnection.GetServerId();
                if (resp != 0)
                {
                    await ControlConnection.AddHooks(MessageFactory.OpcodesList);
                    OnNewConnection(BasicTeraData.Instance.Servers.GetServer(resp));
                    var rv = await ControlConnection.GetReleaseVersion();
                    ReleaseVersionUpdated?.Invoke(rv);
                    _dataConnection = new TcpClient();
                    await _dataConnection.ConnectAsync("127.0.0.60", 5301);
                }
                else
                {
                    await Task.Delay(100);
                    continue;
                }
                var stream = _dataConnection.GetStream();

                Connected = true;
                while (Connected)
                {
                    try
                    {
                        var lenBuf = new byte[2];
                        stream.Read(lenBuf, 0, 2);
                        var len = BitConverter.ToUInt16(lenBuf, 0);
                        if (len <= 2)
                        {
                            if (!_dataConnection.IsConnected())
                            {
                                _dataConnection.Close();
                                Connected = false;
                            }
                            continue;
                        }
                        var length = len - 2;
                        var dataBuf = new byte[length];

                        var progress = 0;
                        while (progress < length)
                        {
                            progress += stream.Read(dataBuf, progress, length - progress);
                        }
                        OnMessageReceived(
                            new Message(
                                DateTime.UtcNow,
                                MessageDirection.Unspecified,
                                new ArraySegment<byte>(dataBuf)
                            )
                        );
                    }
                    catch
                    {
                        _dataConnection.Close();
                        Connected = false;
                    }
                }
            }
        }
#endif
    }

    public class TeraSniffer : BaseSniffer
    {
        //private static TeraSniffer _instance;

        // Only take this lock in callbacks from tcp sniffing, not in code that can be called by the user.
        // Otherwise this could cause a deadlock if the user calls such a method from a callback that already holds a lock
        //private readonly object _eventLock = new object();
        private readonly IpSniffer _ipSniffer;

        private readonly ConcurrentDictionary<TcpConnection, byte> _isNew =
            new ConcurrentDictionary<TcpConnection, byte>();

        private readonly Dictionary<string, Server> _serversByIp;
        private readonly bool _debugLogPackets = true;
        private void DebugLogPacket(MessageDirection direction, byte[] dataBuf)
        {
            try
            {
                // TERA packet layout: uint16 len, uint16 opcode (little-endian)
                if (dataBuf == null || dataBuf.Length < 4) return;
                var op = BitConverter.ToUInt16(dataBuf, 2);
                System.Diagnostics.Debug.WriteLine($"[Shinra][Unencrypted] dir={direction} len={dataBuf.Length} op=0x{op:X4}");
            }
            catch { /* best-effort debug logging */ }
        }
        private TcpConnection _clientToServer;
        private ConnectionDecrypter _decrypter;
        private MessageSplitter _messageSplitter;
        private TcpConnection _serverToClient;
        public int ClientProxyOverhead;
        public int ServerProxyOverhead;

        // Unencrypted socket mode fields
        private readonly bool _unencryptedMode;
        private readonly string _socketHost = "127.0.0.1";
        private readonly int _socketPort = 7802;
        private readonly bool _isUnencrypted = true; // reserved for future toggles
        private CancellationTokenSource _socketCts;
        private Task _socketTask;

        private bool _connected;
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

        public TeraSniffer()
        {
            var servers = BasicTeraData.Instance.Servers;
            _serversByIp = servers.GetServersByIp();

            BasicTeraData.Instance.WindowData.CaptureMode = CaptureMode.Npcap;
            if (BasicTeraData.Instance.WindowData.CaptureMode == CaptureMode.Npcap)
            {
                var netmasks = _serversByIp
                    .Keys.Select(s => string.Join(".", s.Split('.').Take(3)) + ".0/24")
                    .Distinct()
                    .ToArray();

                var filter = string.Join(" or ", netmasks.Select(x => $"(net {x})"));
                filter = "tcp and (" + filter + ")";

                try //fallback to raw sockets if no winpcap available
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

        // Unencrypted socket constructor - if unencryptedMode is true, skip raw sniffer setup
        public TeraSniffer(
            bool unencryptedMode,
            string socketHost = "127.0.0.1",
            int socketPort = 7802,
            bool isUnencrypted = true
        )
        {
            _unencryptedMode = unencryptedMode;
            _socketHost = socketHost;
            _socketPort = socketPort;
            _isUnencrypted = isUnencrypted;

            var servers = BasicTeraData.Instance.Servers;
            _serversByIp = servers.GetServersByIp();

            if (!_unencryptedMode)
            {
                BasicTeraData.Instance.WindowData.CaptureMode = CaptureMode.Npcap;
                if (BasicTeraData.Instance.WindowData.CaptureMode == CaptureMode.Npcap)
                {
                    var netmasks = _serversByIp
                        .Keys.Select(s => string.Join(".", s.Split('.').Take(3)) + ".0/24")
                        .Distinct()
                        .ToArray();

                    var filter = string.Join(" or ", netmasks.Select(x => $"(net {x})"));
                    filter = "tcp and (" + filter + ")";

                    try //fallback to raw sockets if no winpcap available
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
        }

        //public static TeraSniffer Instance => _instance ?? (_instance = new TeraSniffer());

        // IpSniffer has its own locking, so we need no lock here.
        public override bool Enabled
        {
            get =>
                _unencryptedMode
                    ? (_socketTask != null && !_socketTask.IsCompleted)
                    : _ipSniffer.Enabled;
            set
            {
                if (_unencryptedMode)
                {
                    if (value)
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
                    {
                        _socketCts?.Cancel();
                    }
                }
                else
                {
                    _ipSniffer.Enabled = value;
                }
            }
        }

        public override void CleanupForcefully()
        {
            _clientToServer?.RemoveCallback();
            _serverToClient?.RemoveCallback();
            if (_unencryptedMode)
            {
                try
                {
                    _socketCts?.Cancel();
                }
                catch { }
            }
            base.CleanupForcefully();
            //_instance.Enabled = false;
            //_instance = null;
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
                connection.RemoveCallback();
            connection.DataReceived -= HandleTcpDataReceived;
        }

        // called from the tcp sniffer, so it needs to lock
        private void HandleNewConnection(TcpConnection connection)
        {
            {
                if (
                    Connected
                    || !_serversByIp.ContainsKey(connection.Destination.Address.ToString())
                        && !_serversByIp.ContainsKey(connection.Source.Address.ToString())
                )
                {
                    return;
                }
                _isNew.TryAdd(connection, 1);
                connection.DataReceived += HandleTcpDataReceived;
            }
        }

        // called from the tcp sniffer, so it needs to lock
        private void HandleTcpDataReceived(TcpConnection connection, byte[] data, int needToSkip)
        {
            {
                if (data.Length == 0)
                {
                    if (
                        needToSkip == 0
                        || !(connection == _clientToServer || connection == _serverToClient)
                    )
                    {
                        return;
                    }
                    _decrypter?.Skip(
                        connection == _clientToServer
                            ? MessageDirection.ClientToServer
                            : MessageDirection.ServerToClient,
                        needToSkip
                    );
                    return;
                }
                if (!Connected && _isNew.ContainsKey(connection))
                {
                    if (
                        _serversByIp.ContainsKey(connection.Source.Address.ToString())
                        && data.Take(4).SequenceEqual(new byte[] { 1, 0, 0, 0 })
                    )
                    {
                        byte q;
                        _isNew.TryRemove(connection, out q);
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
                    if (
                        _serverToClient != null
                        && _clientToServer == null
                        && _serverToClient.Destination.Equals(connection.Source)
                        && _serverToClient.Source.Equals(connection.Destination)
                    )
                    {
                        ClientProxyOverhead = (int)connection.BytesReceived;
                        byte q;
                        _isNew.TryRemove(connection, out q);
                        _clientToServer = connection;
                        var server = _serversByIp[connection.Destination.Address.ToString()];
                        _isNew.Clear();
                        OnNewConnection(server);
                    }
                    if (connection.BytesReceived > 0x10000) //if received more bytes but still not recognized - not interesting.
                    {
                        byte q;
                        _isNew.TryRemove(connection, out q);
                        connection.DataReceived -= HandleTcpDataReceived;
                        connection.RemoveCallback();
                    }
                }

                if (!(connection == _clientToServer || connection == _serverToClient))
                {
                    return;
                }
                if (_decrypter == null)
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
                    }
                    catch (Exception e)
                    {
                        BasicTeraData.LogError(e.Message + "\r\n" + e.StackTrace, true);
                        CleanupForcefully();
                    }
                    return;
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

        // called indirectly from HandleTcpDataReceived, so the current thread already holds the lock
        private void HandleServerToClientDecrypted(byte[] data)
        {
            _messageSplitter.ServerToClient(DateTime.UtcNow, data);
        }

        // called indirectly from HandleTcpDataReceived, so the current thread already holds the lock
        private void HandleClientToServerDecrypted(byte[] data)
        {
            _messageSplitter.ClientToServer(DateTime.UtcNow, data);
        }

        // Unencrypted socket mode: connect to a socket and feed decrypted frames
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
                            continue; // minimal sane frame size

                        var dirBuf = new byte[1];
                        if (!ReadExact(stream, dirBuf, 1))
                            break;
                        byte direction = dirBuf[0];

                        int frameLen = totalLen; // equals (1 + teraLen) by spec
                        // Read the inner TERA length field as provided by the mirror
                        var lenField = new byte[2];
                        if (!ReadExact(stream, lenField, 2))
                            break;
                        var teraPacketLen = BitConverter.ToUInt16(lenField, 0);
                        // Sanity: transportLen should be 1 (dir) + teraPacketLen
                        if (teraPacketLen < 4 || 1 + teraPacketLen != frameLen)
                        {
                            OnWarning($"[Unencrypted] transport/tera length mismatch: transportLen={frameLen}, teraLen={teraPacketLen}");
                        }

                        // Read opcode+payload (teraLen includes its own 2 bytes of length)
                        var restLen = teraPacketLen - 2;
                        var restBuf = new byte[restLen];
                        if (!ReadExact(stream, restBuf, restLen))
                            break;

                        // Reconstruct full TERA packet [len(2)][opcode(2)][payload...]
                        var dataBuf = new byte[teraPacketLen];
                        Buffer.BlockCopy(lenField, 0, dataBuf, 0, 2);
                        if (restLen > 0)
                            Buffer.BlockCopy(restBuf, 0, dataBuf, 2, restLen);

                        packets++;
                        if (packets == 1)
                        {
                            var server = new Tera.Game.Server("Yurian", "EUC", _socketHost);
                            _messageSplitter = new MessageSplitter();
                            _messageSplitter.MessageReceived += HandleMessageReceived;
                            // Wire Resync diagnostics in unencrypted mode for visibility into framing issues
                            _messageSplitter.Resync += OnResync;
                            OnNewConnection(server);

                            // MessageFactory will be initialized on the Core side (PacketProcessor.HandleNewConnection)
                        }

                        // Validate direction marker explicitly (1=C2S, 2=S2C)
                        MessageDirection msgDir;
                        if (direction == 1)
                        {
                            msgDir = MessageDirection.ClientToServer;
                        }
                        else if (direction == 2)
                        {
                            msgDir = MessageDirection.ServerToClient;
                        }
                        else
                        {
                            OnWarning(
                                $"[Unencrypted] Unknown direction byte={direction}, skipping frame of totalLen={totalLen}"
                            );
                            continue;
                        }

                        // Validate inner TERA length matches the data buffer we pass to the splitter
                        if (dataBuf.Length >= 2)
                        {
                            var innerLen = BitConverter.ToUInt16(dataBuf, 0);
                            if (innerLen != dataBuf.Length)
                            {
                                OnWarning(
                                    $"[Unencrypted] Inner TERA len mismatch: innerLen={innerLen} dataLen={dataBuf.Length} (totalLen={totalLen}, dir={direction}). Possible framing mismatch."
                                );
                                // Fallback: if innerLen looks sane and smaller than dataLen, trim to innerLen to try to recover this frame
                                if (innerLen >= 4 && innerLen <= dataBuf.Length)
                                {
                                    var trimmed = new byte[innerLen];
                                    Buffer.BlockCopy(dataBuf, 0, trimmed, 0, innerLen);
                                    dataBuf = trimmed;
                                }
                            }
                        }

                        // if (_debugLogPackets) DebugLogPacket(msgDir, dataBuf);
                        if (msgDir == MessageDirection.ClientToServer)
                            _messageSplitter.ClientToServer(DateTime.UtcNow, dataBuf);
                        else
                            _messageSplitter.ServerToClient(DateTime.UtcNow, dataBuf);
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
