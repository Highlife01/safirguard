using System;
using System.IO;
using System.Collections.Generic;
using Microsoft.Win32;
using SafirGuard.App.Models;

namespace SafirGuard.App.Autoruns
{
    /// <summary>
    /// Safir Power Eraser Derin Kalıcılık & Windows Başlangıç (Autoruns) Temizleyicisi
    /// </summary>
    public class DeepPersistenceCleaner
    {
        public List<AutorunItem> ScanStartupEntries()
        {
            var entries = new List<AutorunItem>();

            // 1. Registry Run & RunOnce Anahtarları
            if (OperatingSystem.IsWindows())
            {
                ScanRegistryKey(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", entries);
                ScanRegistryKey(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce", entries);
                ScanRegistryKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", entries);
                ScanRegistryKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce", entries);
            }

            // 2. Startup Klasörleri
            string userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            string commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);

            ScanFolder(userStartup, "User Startup Folder", entries);
            ScanFolder(commonStartup, "Common Startup Folder", entries);

            return entries;
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private void ScanRegistryKey(RegistryKey rootKey, string subKeyPath, string locationName, List<AutorunItem> list)
        {
            try
            {
                using var key = rootKey.OpenSubKey(subKeyPath);
                if (key == null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    object? val = key.GetValue(valueName);
                    if (val == null) continue;

                    string cmd = val.ToString() ?? string.Empty;
                    var (risk, reasons) = EvaluateStartupEntry(valueName, cmd);

                    list.Add(new AutorunItem
                    {
                        Name = valueName,
                        Command = cmd,
                        Location = locationName,
                        SourceType = "Registry",
                        RiskLevel = risk,
                        Reasons = reasons
                    });
                }
            }
            catch
            {
                // Registry erişim izni
            }
        }

        private void ScanFolder(string folderPath, string locationName, List<AutorunItem> list)
        {
            if (!Directory.Exists(folderPath)) return;

            try
            {
                foreach (var file in Directory.GetFiles(folderPath))
                {
                    string fileName = Path.GetFileName(file);
                    if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;

                    var (risk, reasons) = EvaluateStartupEntry(fileName, file);

                    list.Add(new AutorunItem
                    {
                        Name = fileName,
                        Command = file,
                        Location = locationName,
                        SourceType = "Startup Folder",
                        RiskLevel = risk,
                        Reasons = reasons
                    });
                }
            }
            catch
            {
                // Klasör okuma izni
            }
        }

        private (string risk, List<string> reasons) EvaluateStartupEntry(string name, string cmd)
        {
            var reasons = new List<string>();
            string cmdLower = cmd.ToLowerInvariant();
            string nameLower = name.ToLowerInvariant();

            if (cmdLower.Contains(@"\appdata\local\temp") || cmdLower.Contains(@"\windows\temp"))
            {
                reasons.Add("Başlangıçta Geçici (%TEMP%) Dizininden Çalışıyor (Yüksek Risk)");
            }

            if (cmdLower.EndsWith(".vbs") || cmdLower.EndsWith(".bat") || cmdLower.EndsWith(".ps1") || cmdLower.EndsWith(".cmd"))
            {
                reasons.Add("Başlangıçta Doğrudan Script Yürütülüyor");
            }

            if (cmdLower.Contains("powershell") && (cmdLower.Contains("-enc") || cmdLower.Contains("-hidden") || cmdLower.Contains("bypass")))
            {
                reasons.Add("Gizli/Yetki Aşımlı PowerShell Başlatıcı Argümanı");
            }

            string risk = "Safe";
            if (reasons.Count >= 2 || reasons.Any(r => r.Contains("Geçici (%TEMP%)")))
            {
                risk = "High";
            }
            else if (reasons.Count > 0)
            {
                risk = "Suspicious";
            }

            return (risk, reasons);
        }
    }
}
