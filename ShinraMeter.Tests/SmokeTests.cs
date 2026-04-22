using System;
using System.Collections.Generic;
using System.IO;
using Tera;
using Tera.Game;
using Tera.Game.Messages;

namespace ShinraMeter.Tests;

public class SmokeTests
{
    [Fact]
    public void HarnessRuns()
    {
        Assert.Equal(4, 2 + 2);
    }

    [Fact]
    public void EachSkillResult_ClassicPlus10002_ReadsAmountAfterOriginalSkillId()
    {
        var opcodeNamer = new OpCodeNamer(new Dictionary<ushort, string>
        {
            { 1, "S_EACH_SKILL_RESULT" },
        });
        var factory = new MessageFactory(opcodeNamer, "EUC", 387400);
        factory.ReleaseVersion = 10002;

        var message = new Message(
            DateTime.UtcNow,
            MessageDirection.ServerToClient,
            new ArraySegment<byte>(BuildEachSkillResultPacket(opcode: 1, amount: 123L))
        );

        var parsed = (EachSkillResultServerMessage)factory.Create(message);

        Assert.Equal(123L, parsed.Amount);
        Assert.Equal(0x1234567, parsed.SkillId);
    }

    [Fact]
    public void LoginArbiter_ClassicPlusAlwaysPinsReleaseVersion10002()
    {
        var opcodeNamer = new OpCodeNamer(new Dictionary<ushort, string>
        {
            { 2, "C_LOGIN_ARBITER" },
        });
        var factory = new MessageFactory(opcodeNamer, "EUC", 387400);
        factory.ReleaseVersion = 9901;

        var message = new Message(
            DateTime.UtcNow,
            MessageDirection.ClientToServer,
            new ArraySegment<byte>(BuildLoginArbiterPacket(opcode: 2, language: 6, fallbackVersion: 2707))
        );

        _ = (C_LOGIN_ARBITER)factory.Create(message);

        Assert.Equal(10002, factory.ReleaseVersion);
    }

    [Fact]
    public void TeraSniffer_UsesPacketSnifferPath_NotMirrorSocketPath()
    {
        var source = File.ReadAllText(
            Path.Combine(
                AppContext.BaseDirectory,
                "..",
                "..",
                "..",
                "..",
                "DamageMeter.Sniffing",
                "TeraSniffer.cs"
            )
        );

        Assert.Contains("new TcpSniffer(_ipSniffer)", source);
        Assert.Contains("new IpSnifferRawSocketMultipleInterfaces()", source);
        Assert.DoesNotContain("ConnectAsync(_socketHost, _socketPort)", source);
    }

    private static byte[] BuildEachSkillResultPacket(ushort opcode, long amount)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write(opcode);
        writer.Write(0); // skip 4
        writer.Write((ulong)1); // source
        writer.Write((ulong)0); // owner
        writer.Write((ulong)2); // target
        writer.Write(999); // template id
        writer.Write((ulong)0x1234567); // skill id
        writer.Write((ulong)0x7654321); // original skill id (present on Classic+ v100)
        writer.Write(7); // hit id
        writer.Write(new byte[12]); // unknown2
        writer.Write(amount); // amount (int64)
        writer.Write(1); // flags debug
        writer.Write((byte)0); // crit
        writer.Write((byte)0); // consume edge
        writer.Write((byte)0); // blocked
        writer.Write(0); // super armor id
        writer.Write(0); // hit cylinder id
        writer.Write(0); // reaction bools pad
        writer.Write((short)0); // skill damage type pad
        writer.Write(0f); // pos x
        writer.Write(0f); // pos y
        writer.Write(0f); // pos z
        writer.Write((short)0); // heading

        writer.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildLoginArbiterPacket(ushort opcode, uint language, int fallbackVersion)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write(opcode);
        writer.Write(new byte[11]);
        writer.Write(language);
        writer.Write(fallbackVersion);

        writer.Flush();
        return ms.ToArray();
    }
}
