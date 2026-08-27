using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using SafirGuard.App.Models;

namespace SafirGuard.App.Engine
{
    public class SignatureScanner
    {
        private class SignatureEntry
        {
            public string Name { get; set; } = string.Empty;
            public string Type { get; set; } = "Malware";
            public string Sha256 { get; set; } = string.Empty;
            public string Md5 { get; set; } = string.Empty;
            public string Severity { get; set; } = "High";
            public string Description { get; set; } = string.Empty;
        }

        private class PatternEntry
        {
            public string Name { get; set; } = string.Empty;
            public string Type { get; set; } = "Malware";
            public string Pattern { get; set; } = string.Empty;
            public string Severity { get; set; } = "High";
            public string Description { get; set; } = string.Empty;
        }

        private readonly List<SignatureEntry> _signatures = new();
        private readonly List<PatternEntry> _patterns = new();

        public SignatureScanner()
        {
            LoadDefaultSignatures();
        }

        private void LoadDefaultSignatures()
        {
            // 1. Bilinen Hash İmzaları
            _signatures.Add(new SignatureEntry
            {
                Name = "EICAR-Test-File (Standard Antivirus Test Sample)",
                Type = "Test.Antivirus",
                Sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                Md5 = "44d88612fea8a8f36de82e1278abb02f",
                Severity = "Low",
                Description = "Zararsız standart antivirüs test dosyası."
            });

            _signatures.Add(new SignatureEntry
            {
                Name = "Trojan.Ransomware.WannaCrySample",
                Type = "Ransomware",
                Sha256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
                Md5 = "db349b97c37d22f5b0d0fed84918ce06",
                Severity = "Critical",
                Description = "Bilinen WannaCry fidye yazılımı türevi."
            });

            _signatures.Add(new SignatureEntry
            {
                Name = "CoinMiner.XMRig.Payload",
                Type = "Cryptominer",
                Sha256 = "a3b9348ec7891823908234890283409823490823094820934823094823094820",
                Severity = "High",
                Description = "İzinsiz arkaplan kripto para madencisi."
            });

            // 2. İçerik ve Desen Kalıpları
            _patterns.Add(new PatternEntry
            {
                Name = "Safir.Standard.Test.Signature",
                Type = "Test.Antivirus",
                Pattern = "SAFIR-ANTIVIRUS-STANDARD-TEST-SAMPLE",
                Severity = "Low",
                Description = "SafirGuard güvenli antivirüs test imzası."
            });

            _patterns.Add(new PatternEntry
            {
                Name = "EICAR-Standard-Test-Signature",
                Type = "Test.Antivirus",
                Pattern = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
                Severity = "Low",
                Description = "Standart EICAR test dizesi."
            });

            _patterns.Add(new PatternEntry
            {
                Name = "HackTool.Mimikatz.LogonPasswords",
                Type = "HackTool/CredentialTheft",
                Pattern = "sekurlsa::logonpasswords",
                Severity = "Critical",
                Description = "Windows bellekten parola çalma aracı imzası."
            });

            _patterns.Add(new PatternEntry
            {
                Name = "Backdoor.Webshell.GenericPHP",
                Type = "Webshell",
                Pattern = "eval(base64_decode($_POST[",
                Severity = "High",
                Description = "PHP uzaktan kod çalıştırma arka kapısı."
            });

            _patterns.Add(new PatternEntry
            {
                Name = "Trojan.PowerShell.HiddenExecution",
                Type = "Malicious Script",
                Pattern = "-WindowStyle Hidden -ExecutionPolicy Bypass -Enc",
                Severity = "High",
                Description = "Gizlenmiş ve şifrelenmiş PowerShell çalıştırma kalıbı."
            });
        }

        public (string sha256, string md5) CalculateHashes(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var sha = SHA256.Create();
                using var md5 = MD5.Create();

                byte[] shaBytes = sha.ComputeHash(stream);
                stream.Position = 0;
                byte[] md5Bytes = md5.ComputeHash(stream);

                return (
                    Convert.ToHexString(shaBytes).ToLowerInvariant(),
                    Convert.ToHexString(md5Bytes).ToLowerInvariant()
                );
            }
            catch
            {
                return (string.Empty, string.Empty);
            }
        }

        public ThreatItem? ScanFile(string filePath)
        {
            if (!File.Exists(filePath)) return null;

            try
            {
                var (sha256, md5) = CalculateHashes(filePath);

                // 1. Hash Eşleşmesi
                foreach (var sig in _signatures)
                {
                    if ((!string.IsNullOrEmpty(sig.Sha256) && sig.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase)) ||
                        (!string.IsNullOrEmpty(sig.Md5) && sig.Md5.Equals(md5, StringComparison.OrdinalIgnoreCase)))
                    {
                        return new ThreatItem
                        {
                            ThreatName = sig.Name,
                            ThreatType = sig.Type,
                            Severity = sig.Severity,
                            DetectionMethod = "Safir Signature & Hash Engine",
                            FilePath = filePath,
                            Description = sig.Description,
                            Sha256 = sha256
                        };
                    }
                }

                // 2. İçerik ve Desen Eşleşmesi (10 MB'a kadar dosyalar için hızlı okuma)
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length < 10 * 1024 * 1024)
                {
                    byte[] fileBytes = File.ReadAllBytes(filePath);
                    string rawText = Encoding.UTF8.GetString(fileBytes);

                    foreach (var pat in _patterns)
                    {
                        if (rawText.Contains(pat.Pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            return new ThreatItem
                            {
                                ThreatName = pat.Name,
                                ThreatType = pat.Type,
                                Severity = pat.Severity,
                                DetectionMethod = "Signature Pattern Matcher",
                                FilePath = filePath,
                                Description = pat.Description,
                                Sha256 = sha256
                            };
                        }
                    }
                }
            }
            catch
            {
                // Dosya kilitli veya erişim engelli
            }

            return null;
        }
    }
}
