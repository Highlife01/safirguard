using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using SafirGuard.App.Models;

namespace SafirGuard.App.Engine
{
    /// <summary>
    /// Safir Sentinel Çok Faktörlü İtibar ve Davranışsal Risk Skorlama Motoru
    /// </summary>
    public class SonarReputationEngine
    {
        public ThreatItem? AnalyzeFileReputation(string filePath)
        {
            if (!File.Exists(filePath)) return null;

            try
            {
                var fileInfo = new FileInfo(filePath);
                string fileName = fileInfo.Name.ToLowerInvariant();
                string fullPath = fileInfo.FullName.ToLowerInvariant();
                string ext = fileInfo.Extension.ToLowerInvariant();

                int riskScore = 0;
                List<string> sonarFactors = new();

                // 1. Çift Uzantı Hilesi (.pdf.exe, .jpg.scr, .docx.vbs)
                if (Regex.IsMatch(fileName, @"\.(pdf|docx|xlsx|jpg|png|txt)\.(exe|scr|vbs|bat|cmd|ps1|hta|wsf)$"))
                {
                    riskScore += 50;
                    sonarFactors.Add("Kullanıcıyı Yanıltıcı Çift Uzantı Hilesi (Double Extension Camouflage)");
                }

                // 2. Riskli Çalışma Dizinleri (%TEMP%, AppData\Local\Temp)
                if (fullPath.Contains(@"\appdata\local\temp") || fullPath.Contains(@"\windows\temp"))
                {
                    riskScore += 25;
                    sonarFactors.Add("Geçici (%TEMP%) Dizininde Barınıyor");
                }

                // 3. Dosya Nitelikleri (Gizli + Sistem Nitelikli Çalıştırılabilir)
                if ((fileInfo.Attributes & FileAttributes.Hidden) != 0 && (ext == ".exe" || ext == ".vbs" || ext == ".ps1"))
                {
                    riskScore += 20;
                    sonarFactors.Add("Gizli (Hidden) Nitelikli Çalıştırılabilir Dosya");
                }

                // 4. Script İçi Şüpheli Davranış Kalıpları
                if (ext == ".ps1" || ext == ".vbs" || ext == ".bat" || ext == ".cmd" || ext == ".js" || ext == ".hta")
                {
                    string scriptContent = File.ReadAllText(filePath);

                    if (Regex.IsMatch(scriptContent, @"powershell.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}", RegexOptions.IgnoreCase))
                    {
                        riskScore += 45;
                        sonarFactors.Add("Base64 ile Gizlenmiş PowerShell Komut Yükü");
                    }

                    if (Regex.IsMatch(scriptContent, @"vssadmin.*delete.*shadows", RegexOptions.IgnoreCase))
                    {
                        riskScore += 65;
                        sonarFactors.Add("Ransomware Gölge Kopya (Shadow Copy) İmha Komutu");
                    }

                    if (Regex.IsMatch(scriptContent, @"downloadstring|downloaddata|Invoke-WebRequest", RegexOptions.IgnoreCase))
                    {
                        riskScore += 25;
                        sonarFactors.Add("Uzaktan Zararlı İndirici (Dropper/Downloader) Çağrısı");
                    }
                }

                if (riskScore >= 45)
                {
                    string severity = riskScore >= 70 ? "Critical" : (riskScore >= 55 ? "High" : "Medium");
                    return new ThreatItem
                    {
                        ThreatName = riskScore >= 60 ? "Safir.Sentinel.HighRiskPayload" : "Safir.Sentinel.SuspiciousActivity",
                        ThreatType = "Heuristic Risk",
                        Severity = severity,
                        DetectionMethod = "Safir Sentinel Multi-Factor Reputation Engine",
                        FilePath = filePath,
                        Description = $"Sentinel İtibar Analizi (Skor: {riskScore}/100): {string.Join("; ", sonarFactors)}"
                    };
                }
            }
            catch
            {
                // Dosya okuma hatası
            }

            return null;
        }
    }
}
