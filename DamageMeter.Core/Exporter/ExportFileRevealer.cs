using System;
using System.Diagnostics;
using Data;

namespace DamageMeter
{
    internal static class ExportFileRevealer
    {
        public static void Reveal(string filePath)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{filePath}\"",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                BasicTeraData.LogError("Could not reveal exported file: " + ex.Message, false, true);
            }
        }
    }
}
