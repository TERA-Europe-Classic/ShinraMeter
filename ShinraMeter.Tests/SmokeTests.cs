using System;
using System.Collections.Generic;
using System.IO;
using Data.Actions.Notify.SoundElements;
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
    public void EachSkillResult_ClassicPlus10002_ReadsAmountFromToolboxV14Layout()
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
        Assert.Equal(7, parsed.HitId);
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
    public void TeraSniffer_UsesMirrorSocketPath_NotPacketSnifferPath()
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

        Assert.Contains("_socketHost = \"127.0.0.1\"", source);
        Assert.Contains("ConnectAsync(_socketHost, _socketPort)", source);
        Assert.Contains("if (direction == 1)", source);
        Assert.Contains("else if (direction == 2)", source);
        Assert.DoesNotContain("new TcpSniffer(_ipSniffer)", source);
    }

    [Fact]
    public void ClassicPlusServerId2800_ResolvesToElinu()
    {
        var serverDatabase = new ServerDatabase(ProjectPath("resources", "data"))
        {
            Language = LangEnum.EU_EN,
        };

        Assert.Equal("Elinu", serverDatabase.GetServerName(2800));
    }

    [Fact]
    public void TextToSpeech_CanBeDisabledPerAlert()
    {
        var tts = new TextToSpeech("Use Nostrum", VoiceGender.Female, VoiceAge.Adult, 0, "en-US", 30, 0, false);

        Assert.False(tts.Enabled);
    }

    [Fact]
    public void EventsParser_ReadsTextToSpeechEnabledAttributeWithDefaultEnabled()
    {
        var source = File.ReadAllText(ProjectPath("Data", "EventsData.cs"));

        Assert.Contains("tts.Attribute(\"enabled\")?.Value ?? \"True\"", source);
        Assert.Contains("new TextToSpeech(text, voiceGender, voiceAge, voicePosition, culture, volume, rate, enabled)", source);
        Assert.Contains("new XAttribute(\"enabled\", textToSpeech.Enabled)", source);
    }

    [Fact]
    public void EventsEditor_ExposesPerTextToSpeechToggle()
    {
        var viewModelSource = File.ReadAllText(ProjectPath("DamageMeter.UI", "EventsEditor", "TtsDataVM.cs"));
        var editorSource = File.ReadAllText(ProjectPath("DamageMeter.UI", "EventsEditor", "EventsEditorViewModel.cs"));
        var xamlSource = File.ReadAllText(ProjectPath("DamageMeter.UI", "EventsEditor", "EventsEditorWindow.xaml"));

        Assert.Contains("public bool Enabled", viewModelSource);
        Assert.Contains("_data.Save();", editorSource);
        Assert.Contains("IsOn=\"{Binding Enabled, Mode=TwoWay}\"", xamlSource);
    }

    [Fact]
    public void ManualJsonAndExcelExportsRevealTheCreatedFileInExplorer()
    {
        var jsonSource = File.ReadAllText(ProjectPath("DamageMeter.Core", "Exporter", "JsonExporter.cs"));
        var excelSource = File.ReadAllText(ProjectPath("DamageMeter.Core", "Exporter", "ExcelExporter.cs"));
        var revealerSource = File.ReadAllText(ProjectPath("DamageMeter.Core", "Exporter", "ExportFileRevealer.cs"));

        Assert.Contains("if (manual) { ExportFileRevealer.Reveal(fname); }", jsonSource);
        Assert.Contains("if (manual) { ExportFileRevealer.Reveal(fname); }", excelSource);
        Assert.Contains("explorer.exe", revealerSource);
        Assert.Contains("/select,", revealerSource);
    }

    [Fact]
    public void WpfAppExitPersistsSettingsWhenMainWindowIsClosedExternally()
    {
        var appSource = File.ReadAllText(ProjectPath("DamageMeter.UI", "App.xaml.cs"));

        var appExitBody = appSource.Substring(appSource.IndexOf("private void App_OnExit", StringComparison.Ordinal));

        Assert.Contains("HudContainer?.SaveWindowsPos()", appExitBody);
        Assert.Contains("BasicTeraData.Instance.WindowData.Save()", appExitBody);
        Assert.Contains("BasicTeraData.Instance.WindowData.Close()", appExitBody);
        Assert.Contains("BasicTeraData.Instance.HotkeysData.Save()", appExitBody);
    }

    private static string ProjectPath(params string[] parts)
    {
        var pathParts = new List<string>
        {
            AppContext.BaseDirectory,
            "..",
            "..",
            "..",
            "..",
        };
        pathParts.AddRange(parts);

        return Path.GetFullPath(Path.Combine(pathParts.ToArray()));
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
        writer.Write(7); // hit id
        writer.Write(11); // area
        writer.Write((uint)22); // id
        writer.Write(33); // time
        writer.Write(amount); // amount (int64)
        writer.Write((short)1); // type = damage
        writer.Write((short)0); // noctEffect
        writer.Write((byte)0); // crit
        writer.Write((byte)0); // stackExplode
        writer.Write((byte)0); // superArmor
        writer.Write(0); // super armor id
        writer.Write(0); // hit cylinder id
        writer.Write(new byte[4]); // reaction bools
        writer.Write((short)0); // damage type
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
