using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using SafirGuard.App.Models;

namespace SafirGuard.App.Engine
{
    /// <summary>
    /// Safir Sezgisel (Heuristic) PE Dosyası ve Entropi Analiz Motoru
    /// </summary>
    public class HeuristicPeAnalyzer
    {
        private static readonly string[] PackerSections = new[]
        {
            "upx0", "upx1", "upx2", ".vmp0", ".vmp1", ".themida", ".aspack", ".fsg", ".petite"
        };

        private static readonly Dictionary<string, string> SuspiciousApis = new(StringComparer.OrdinalIgnoreCase)
        {
            { "VirtualAllocEx", "Bellek Tahsisi (Memory Injection)" },
            { "WriteProcessMemory", "Süreç Belleği Yazma (Code Injection)" },
            { "CreateRemoteThread", "Uzak İş Parçacığı Yürütme (Process Injection)" },
            { "SetWindowsHookExA", "Klavye/Girdi Dinleme (Keylogger Hook)" },
            { "SetWindowsHookExW", "Klavye/Girdi Dinleme (Keylogger Hook)" },
            { "NtUnmapViewOfSection", "Süreç İçi Boşaltma (Process Hollowing)" },
            { "QueueUserAPC", "Erken APC Enjeksiyonu (Early Bird Injection)" },
            { "IsDebuggerPresent", "Anti-Analiz & Anti-Hata Ayıklama" }
        };

        /// <summary>
        /// Shannon Entropi Değeri Hesaplar (0.0 - 8.0 arası). 7.2 üzeri dosyanın şifreli veya paketli olduğunu gösterir.
        /// </summary>
        public double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0.0;

            int[] byteCounts = new int[256];
            foreach (byte b in data)
            {
                byteCounts[b]++;
            }

            double entropy = 0.0;
            double len = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (byteCounts[i] > 0)
                {
                    double p = byteCounts[i] / len;
                    entropy -= p * Math.Log2(p);
                }
            }

            return Math.Round(entropy, 3);
        }

        public ThreatItem? ScanPeFile(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".scr" && ext != ".cpl")
            {
                return null;
            }

            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                if (fileBytes.Length < 64) return null;

                // DOS Header 'MZ' Kontrolü
                if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A) return null;

                double totalEntropy = CalculateEntropy(fileBytes);
                int score = 0;
                List<string> reasons = new();

                // 1. Genel Entropi Kontrolü
                if (totalEntropy > 7.35)
                {
                    score += 40;
                    reasons.Add($"Yüksek Genel Entropi ({totalEntropy}/8.0) — Olası Şifrelenmiş/Paketlenmiş Zararlı");
                }

                // 2. PE Başlığı ve Bölüm Taraması
                int peOffset = BitConverter.ToInt32(fileBytes, 0x3C);
                if (peOffset > 0 && peOffset + 24 < fileBytes.Length)
                {
                    // 'PE\0\0' kontrolü
                    if (fileBytes[peOffset] == 0x50 && fileBytes[peOffset + 1] == 0x45)
                    {
                        int numSections = BitConverter.ToInt16(fileBytes, peOffset + 6);
                        int optHeaderSize = BitConverter.ToInt16(fileBytes, peOffset + 20);
                        int sectionHeaderStart = peOffset + 24 + optHeaderSize;

                        for (int i = 0; i < numSections && sectionHeaderStart + (i * 40) + 40 <= fileBytes.Length; i++)
                        {
                            int secOffset = sectionHeaderStart + (i * 40);
                            string secName = Encoding.ASCII.GetString(fileBytes, secOffset, 8).Trim('\0', ' ').ToLowerInvariant();

                            foreach (var packer in PackerSections)
                            {
                                if (secName.Contains(packer))
                                {
                                    score += 35;
                                    reasons.Add($"Paketleyici Bölüm İsmi Tespit Edildi: '{secName}'");
                                    break;
                                }
                            }
                        }
                    }
                }

                // 3. Dosya İçi Şüpheli API Dizelerini Tarama (Import strings)
                string rawAscii = Encoding.ASCII.GetString(fileBytes);
                List<string> foundApis = new();
                foreach (var api in SuspiciousApis)
                {
                    if (rawAscii.Contains(api.Key))
                    {
                        foundApis.Add($"{api.Key} ({api.Value})");
                        score += 15;
                    }
                }

                if (foundApis.Count >= 2)
                {
                    reasons.Add($"Şüpheli Win32 API Kombinasyonu: {string.Join(", ", foundApis.GetRange(0, Math.Min(3, foundApis.Count)))}");
                }

                if (score >= 40)
                {
                    string severity = score >= 65 ? "Critical" : (score >= 50 ? "High" : "Medium");
                    return new ThreatItem
                    {
                        ThreatName = score >= 60 ? "Safir.Heur.PackedBinary" : "Safir.Heur.SuspiciousPe",
                        ThreatType = "Suspicious Binary",
                        Severity = severity,
                        DetectionMethod = "Safir Heuristic PE & Entropy Analyzer",
                        FilePath = filePath,
                        Description = $"Sezgisel PE Analizi: {string.Join("; ", reasons)}"
                    };
                }
            }
            catch
            {
                // Dosya meşgul veya okunamıyor
            }

            return null;
        }
    }
}
