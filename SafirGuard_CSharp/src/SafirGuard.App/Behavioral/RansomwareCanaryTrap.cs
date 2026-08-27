using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using SafirGuard.App.Models;

namespace SafirGuard.App.Behavioral
{
    /// <summary>
    /// Safir Anti-Ransomware Canary (Yem/Tuzak) Dosya Savunma Kalkanı
    /// Hassas dizinlere nöbetçi yem dosyalar yerleştirir. Bir ransomware bu dosyayı şifrelemeye veya silmeye kalktığı anda anında alarm üretir.
    /// </summary>
    public class RansomwareCanaryTrap : IDisposable
    {
        private readonly List<string> _trapFiles = new();
        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly Action<ThreatItem> _onRansomwareAlert;
        private const string SentinelToken = "SAFIR_GUARD_SENTINEL_CANARY_TRIPWIRE_V1";

        public bool IsActive { get; private set; } = false;
        public int TriggeredAlertCount { get; private set; } = 0;

        public RansomwareCanaryTrap(Action<ThreatItem> onRansomwareAlert)
        {
            _onRansomwareAlert = onRansomwareAlert;
            DeployCanaryTraps();
        }

        public void DeployCanaryTraps()
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] targetDirs = new[]
            {
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "Documents"),
                Path.Combine(userProfile, "Downloads")
            };

            foreach (var dir in targetDirs)
            {
                if (!Directory.Exists(dir)) continue;

                string trapPath = Path.Combine(dir, "!_safir_guard_canary_vault.dat");
                try
                {
                    if (!File.Exists(trapPath))
                    {
                        File.WriteAllText(trapPath, $"{SentinelToken}\nProtected by SafirGuard Anti-Ransomware Shield.");
                        File.SetAttributes(trapPath, FileAttributes.Hidden | FileAttributes.Archive);
                    }
                    _trapFiles.Add(trapPath);

                    var watcher = new FileSystemWatcher(dir)
                    {
                        Filter = "!_safir_guard_canary_vault.dat",
                        NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                        EnableRaisingEvents = true
                    };

                    watcher.Changed += OnCanaryTampered;
                    watcher.Renamed += OnCanaryRenamed;
                    watcher.Deleted += OnCanaryDeleted;

                    _watchers.Add(watcher);
                }
                catch
                {
                    // Dizin erişim yetkisi
                }
            }

            IsActive = _watchers.Count > 0;
        }

        private void OnCanaryTampered(object sender, FileSystemEventArgs e)
        {
            TriggerAlert(e.FullPath, "Yem (Canary) Dosya Üzerinde Yetkisiz Şifreleme/Değişiklik Girişimi");
        }

        private void OnCanaryRenamed(object sender, RenamedEventArgs e)
        {
            TriggerAlert(e.FullPath, $"Yem (Canary) Dosya İsmi Değiştirildi ({e.OldName} -> {e.Name}) — Olası Fidye Yazılımı Uzantı Değişimi");
        }

        private void OnCanaryDeleted(object sender, FileSystemEventArgs e)
        {
            TriggerAlert(e.FullPath, "Yem (Canary) Dosya İmha Edildi — Şüpheli Toplu Dosya Manipülasyonu");
        }

        private void TriggerAlert(string path, string details)
        {
            TriggeredAlertCount++;
            var threat = new ThreatItem
            {
                ThreatName = "Safir.AntiRansomware.CanaryTripwireTriggered",
                ThreatType = "Active Ransomware Attack",
                Severity = "Critical",
                DetectionMethod = "Safir Behavioral Canary Trap Shield",
                FilePath = path,
                Description = $"⚠️ ACİL FİDYE YAZILIMI ALARMI: {details}"
            };

            _onRansomwareAlert?.Invoke(threat);
        }

        public CanaryTrapStatus GetStatus()
        {
            return new CanaryTrapStatus
            {
                IsActive = IsActive,
                TotalTraps = _trapFiles.Count,
                TriggeredAlerts = TriggeredAlertCount,
                TrapPaths = new List<string>(_trapFiles)
            };
        }

        public void Dispose()
        {
            foreach (var w in _watchers)
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            _watchers.Clear();
            IsActive = false;
        }
    }
}
