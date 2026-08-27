using System;
using System.IO;
using System.Collections.Concurrent;
using System.Collections.Generic;
using SafirGuard.App.Models;

namespace SafirGuard.App.Realtime
{
    /// <summary>
    /// Safir Zero-Day Real-Time I/O Koruma Kalkanı
    /// </summary>
    public class RealtimeFileShield : IDisposable
    {
        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly Func<string, ThreatItem?> _scanFunc;
        private readonly Action<ThreatItem> _onThreatDetected;
        private readonly ConcurrentDictionary<string, DateTime> _lastScanned = new();
        public bool IsActive { get; private set; } = false;

        public RealtimeFileShield(Func<string, ThreatItem?> scanFunc, Action<ThreatItem> onThreatDetected)
        {
            _scanFunc = scanFunc;
            _onThreatDetected = onThreatDetected;
            Start();
        }

        public void Start()
        {
            if (IsActive) return;

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] watchDirs = new[]
            {
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "Downloads")
            };

            foreach (var dir in watchDirs)
            {
                if (!Directory.Exists(dir)) continue;

                try
                {
                    var watcher = new FileSystemWatcher(dir)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                        EnableRaisingEvents = true,
                        IncludeSubdirectories = false
                    };

                    watcher.Created += (s, e) => ProcessPath(e.FullPath);
                    watcher.Changed += (s, e) => ProcessPath(e.FullPath);

                    _watchers.Add(watcher);
                }
                catch { }
            }

            IsActive = _watchers.Count > 0;
        }

        private void ProcessPath(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return;

            // Karantina kasasını veya canary dosyasını atla
            if (filePath.Contains("quarantine_vault") || filePath.Contains("canary_vault")) return;

            DateTime now = DateTime.UtcNow;
            if (_lastScanned.TryGetValue(filePath, out var lastTime) && (now - lastTime).TotalSeconds < 1.5)
            {
                return;
            }
            _lastScanned[filePath] = now;

            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    System.Threading.Thread.Sleep(150); // Dosyanın diske tam yazılması için bekle
                    var threat = _scanFunc(filePath);
                    if (threat != null)
                    {
                        _onThreatDetected(threat);
                    }
                }
                catch { }
            });
        }

        public void Stop()
        {
            foreach (var w in _watchers)
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            _watchers.Clear();
            IsActive = false;
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
