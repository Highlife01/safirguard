using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using SafirGuard.App.Models;

namespace SafirGuard.App.Engine
{
    /// <summary>
    /// Safir SpyGuard Browser Hijacker, LNK Kısayol ve Spyware/Adware Savunma Kalkanı
    /// </summary>
    public class AdwareSpywareShield
    {
        private static readonly string[] AdwareDomains = new[]
        {
            "sweet-page.com",
            "search-protect.com",
            "babylon-toolbar.com",
            "search.myway.com",
            "dealply-installer.net",
            "adrotator-tracker.biz",
            "traffic-direct-ads.xyz",
            "pop-under-network.club"
        };

        public ThreatItem? ScanLnkShortcut(string lnkPath)
        {
            if (!File.Exists(lnkPath) || !lnkPath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                return null;

            try
            {
                byte[] rawBytes = File.ReadAllBytes(lnkPath);
                string text = Encoding.Latin1.GetString(rawBytes).ToLowerInvariant();

                List<string> reasons = new();

                foreach (var domain in AdwareDomains)
                {
                    if (text.Contains(domain))
                    {
                        reasons.Add($"Kısayol Hedefine Adware/Hijacker Alan Adı Yerleştirilmiş: '{domain}'");
                    }
                }

                if ((text.Contains("chrome.exe") || text.Contains("msedge.exe") || text.Contains("firefox.exe")) &&
                    (text.Contains("http://") || text.Contains("https://")))
                {
                    reasons.Add("Tarayıcı Kısayol Parametresine İzinsiz Web Yönlendirmesi Enjekte Edilmiş (Browser Hijacker)");
                }

                if (text.Contains("cmd.exe") || text.Contains("powershell.exe") || text.Contains("wscript.exe"))
                {
                    if (text.Contains("-windowstyle hidden") || text.Contains("-enc") || text.Contains("/c start"))
                    {
                        reasons.Add("Kısayol İçinde Gizli Komut Zinciri (LNK Dropper / Loader)");
                    }
                }

                if (reasons.Count > 0)
                {
                    return new ThreatItem
                    {
                        ThreatName = "Safir.SpyGuard.BrowserHijacker.LNK",
                        ThreatType = "Adware / Browser Hijacker",
                        Severity = "Medium",
                        DetectionMethod = "Safir SpyGuard LNK Hijacker Shield",
                        FilePath = lnkPath,
                        Description = $"SpyGuard Kısayol Analizi: {string.Join("; ", reasons)}"
                    };
                }
            }
            catch
            {
                // Okuma hatası
            }

            return null;
        }

        public ThreatItem? ScanAdwareContent(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext != ".js" && ext != ".html" && ext != ".htm" && ext != ".json" && ext != ".txt" && ext != ".ini")
                return null;

            try
            {
                var info = new FileInfo(filePath);
                if (info.Length > 5 * 1024 * 1024) return null;

                string content = File.ReadAllText(filePath).ToLowerInvariant();
                List<string> findings = new();

                foreach (var domain in AdwareDomains)
                {
                    if (content.Contains(domain))
                    {
                        findings.Add($"Bilinen Adware Alan Adı İletişimi: {domain}");
                    }
                }

                if (content.Contains("coinhive.min.js") || content.Contains("cryptoloot.pro") || content.Contains("webminepool"))
                {
                    findings.Add("Tarayıcı Tabanlı Web Kripto Para Madencisi (In-Browser CoinMiner)");
                }

                if (content.Contains("window.__ad_injector_tracker_config") || content.Contains("ad_popup_loader"))
                {
                    findings.Add("İzinsiz Popup & Reklam Enjektör Scripti");
                }

                if (findings.Count > 0)
                {
                    return new ThreatItem
                    {
                        ThreatName = "Safir.SpyGuard.AdwarePayload",
                        ThreatType = "Adware / Spyware",
                        Severity = "Medium",
                        DetectionMethod = "Safir SpyGuard Pattern & Spyware Engine",
                        FilePath = filePath,
                        Description = $"SpyGuard Bulgusu: {string.Join("; ", findings)}"
                    };
                }
            }
            catch
            {
                // Dosya okunamadı
            }

            return null;
        }
    }
}
