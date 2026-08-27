using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using SafirGuard.App.Models;

namespace SafirGuard.App.Behavioral
{
    /// <summary>
    /// Safir System Watcher Canlı Süreç ve Davranış Monitörü
    /// </summary>
    public class ProcessBehaviorWatcher
    {
        private static readonly string[] FakeSystemNames = new[]
        {
            "svch0st.exe", "miner.exe", "xmrig.exe", "taskmgr32.exe", "lsasss.exe", "csrss32.exe"
        };

        public List<ProcessItem> ScanRunningProcesses()
        {
            var results = new List<ProcessItem>();
            var processes = Process.GetProcesses();

            foreach (var p in processes)
            {
                try
                {
                    string name = p.ProcessName;
                    string exePath = string.Empty;
                    try
                    {
                        exePath = p.MainModule?.FileName ?? string.Empty;
                    }
                    catch { }

                    double memMb = Math.Round(p.WorkingSet64 / (1024.0 * 1024.0), 1);

                    var (risk, reasons) = EvaluateProcess(name, exePath);

                    results.Add(new ProcessItem
                    {
                        Pid = p.Id,
                        Name = name,
                        ExecutablePath = exePath,
                        MemoryMb = memMb,
                        RiskLevel = risk,
                        Reasons = reasons
                    });
                }
                catch
                {
                    // Süreç sonlanmış veya erişim engelli
                }
            }

            // Riskli ve yüksek bellek kullananları öne sırala
            return results
                .OrderBy(p => p.RiskLevel == "High" ? 1 : (p.RiskLevel == "Suspicious" ? 2 : 3))
                .ThenByDescending(p => p.MemoryMb)
                .ToList();
        }

        private (string risk, List<string> reasons) EvaluateProcess(string name, string exePath)
        {
            var reasons = new List<string>();
            string nameLower = name.ToLowerInvariant();
            string pathLower = exePath.ToLowerInvariant();

            foreach (var fake in FakeSystemNames)
            {
                if (nameLower.Contains(fake.Replace(".exe", "")))
                {
                    reasons.Add($"Sistem İsmi Taklit Eden veya Bilinen Zararlı Süreç Adı: {name}");
                }
            }

            if (pathLower.Contains(@"\appdata\local\temp") || pathLower.Contains(@"\windows\temp"))
            {
                reasons.Add("Geçici (%TEMP%) Dizininden Çalışan Süreç");
            }

            if (pathLower.Contains(@"\downloads\"))
            {
                reasons.Add("İndirilenler Klasöründen Doğrudan Çalıştırılan Uygulama");
            }

            string risk = "Safe";
            if (reasons.Count >= 2 || reasons.Any(r => r.Contains("Zararlı Süreç Adı")))
            {
                risk = "High";
            }
            else if (reasons.Count > 0)
            {
                risk = "Suspicious";
            }

            return (risk, reasons);
        }

        public bool KillProcess(int pid)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                p.Kill(entireProcessTree: true);
                p.WaitForExit(3000);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
