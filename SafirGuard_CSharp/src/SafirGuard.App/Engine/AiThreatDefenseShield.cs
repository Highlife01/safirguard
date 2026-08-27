using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using SafirGuard.App.Models;

namespace SafirGuard.App.Engine
{
    /// <summary>
    /// 🤖 Yapay Zeka (AI) Saldırılarına Karşı Gelişmiş Savunma Motoru (AI Threat Defense Shield)
    /// 1. Prompt Injection & LLM Jailbreak Tespiti
    /// 2. Zararlı Yapay Zeka Model Dosyaları & Güvensiz Pickle/ONNX Deserialization Analizi
    /// 3. Yapay Zeka Üretimi Polimorfik Kod (AI Polymorphic Malware) Tespiti
    /// 4. Sentetik Kimlik Avı (AI Phishing Lures) & Gizli Unicode Manipülasyonları
    /// </summary>
    public class AiThreatDefenseShield
    {
        private static readonly (string Pattern, string Name, int Score, string Desc)[] PromptInjectionPatterns = new[]
        {
            (@"ignore\s+(all\s+)?(previous|prior)\s+instructions", "AI.PromptInjection.SystemOverride", 50, "Önceki talimatları geçersiz kılmaya çalışan Prompt Injection saldırısı"),
            (@"you\s+are\s+now\s+(in\s+)?(dan|developer|god|unrestricted)\s+mode", "AI.Jailbreak.DANMode", 50, "LLM modelini güvenlik filtrelerinden çıkarmaya çalışan Jailbreak dizesi"),
            (@"system\s*prompt\s*:\s*reveal|print\s+your\s+(initial|system)\s+prompt", "AI.PromptLeak.Extraction", 40, "Sistem promptu ve gizli talimatları sızdırma girişimi"),
            (@"\u200B|\u200C|\u200D|\uFEFF|\u202E", "AI.Adversarial.InvisibleUnicode", 35, "Prompt filtrelerini atlatmak için gizli/görünmez Unicode manipülasyonu"),
            (@"bypass\s+(content\s+filter|openai|anthropic|safety\s+guardrails)", "AI.Jailbreak.FilterBypass", 45, "Yapay zeka güvenlik bariyerlerini devre dışı bırakma girişimi")
        };

        private static readonly string[] MaliciousPickleOpcodes = new[]
        {
            "os.system", "cos\nsystem", "cposix\nsystem", "cnt\nsystem", "subprocess.Popen", "csubprocess\nPopen",
            "subprocess.call", "__builtin__.eval", "builtins.exec", "cbuiltins\neval", "cbuiltins\nexec",
            "posix.system", "nt.system", "socket.socket", "urllib.request", "pty.spawn"
        };

        public ThreatItem? ScanAiThreats(string filePath)
        {
            if (!File.Exists(filePath)) return null;

            string ext = Path.GetExtension(filePath).ToLowerInvariant();

            // 1. Yapay Zeka Model Dosyaları Analizi (.pkl, .bin, .pt, .pth, .onnx, .model)
            if (ext == ".pkl" || ext == ".bin" || ext == ".pt" || ext == ".pth" || ext == ".onnx" || ext == ".model")
            {
                var modelThreat = ScanAiModelFile(filePath);
                if (modelThreat != null) return modelThreat;
            }

            // 2. Metin, Kod ve Yapılandırma Dosyalarında Prompt Injection & AI Exploit Taraması
            if (ext == ".txt" || ext == ".json" || ext == ".md" || ext == ".py" || ext == ".yaml" || ext == ".yml" || ext == ".csv" || ext == ".html")
            {
                var promptThreat = ScanPromptInjection(filePath);
                if (promptThreat != null) return promptThreat;
            }

            return null;
        }

        private ThreatItem? ScanAiModelFile(string filePath)
        {
            try
            {
                var info = new FileInfo(filePath);
                if (info.Length > 100 * 1024 * 1024) return null; // 100MB'a kadar derin model başlığı incelemesi

                byte[] bytes = File.ReadAllBytes(filePath);
                string ascii = Encoding.ASCII.GetString(bytes);

                List<string> dangerousHooks = new();
                foreach (var hook in MaliciousPickleOpcodes)
                {
                    if (ascii.Contains(hook, StringComparison.OrdinalIgnoreCase))
                    {
                        dangerousHooks.Add(hook);
                    }
                }

                if (dangerousHooks.Count > 0)
                {
                    return new ThreatItem
                    {
                        ThreatName = "AI.MaliciousModel.PickleRCEPayload",
                        ThreatType = "AI Model Exploitation / RCE",
                        Severity = "Critical",
                        DetectionMethod = "SafirGuard AI Model Security Analyzer",
                        FilePath = filePath,
                        Description = $"🚨 KRİTİK YAPAY ZEKA MODEL TEHDİDİ: Model dosyası içinde uzaktan kod çalıştırma (RCE) kancaları tespit edildi: {string.Join(", ", dangerousHooks)}"
                    };
                }
            }
            catch { }

            return null;
        }

        private ThreatItem? ScanPromptInjection(string filePath)
        {
            try
            {
                var info = new FileInfo(filePath);
                if (info.Length > 10 * 1024 * 1024) return null;

                string content = File.ReadAllText(filePath);
                int score = 0;
                List<string> reasons = new();
                string primaryThreatName = "AI.PromptInjection.Generic";

                foreach (var rule in PromptInjectionPatterns)
                {
                    if (Regex.IsMatch(content, rule.Pattern, RegexOptions.IgnoreCase))
                    {
                        score += rule.Score;
                        reasons.Add(rule.Desc);
                        primaryThreatName = rule.Name;
                    }
                }

                if (score >= 40)
                {
                    string severity = score >= 70 ? "Critical" : (score >= 50 ? "High" : "Medium");
                    return new ThreatItem
                    {
                        ThreatName = primaryThreatName,
                        ThreatType = "AI Adversarial Threat / Prompt Injection",
                        Severity = severity,
                        DetectionMethod = "SafirGuard AI Prompt Shield",
                        FilePath = filePath,
                        Description = $"Yapay Zeka Saldırı Tespiti: {string.Join("; ", reasons)}"
                    };
                }
            }
            catch { }

            return null;
        }
    }
}
