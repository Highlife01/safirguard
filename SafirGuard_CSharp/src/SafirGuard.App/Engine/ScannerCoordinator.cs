using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using SafirGuard.App.Models;
using SafirGuard.App.Quarantine;
using SafirGuard.App.Behavioral;
using SafirGuard.App.Autoruns;
using SafirGuard.App.Network;
using SafirGuard.App.Realtime;
using System.Diagnostics;

namespace SafirGuard.App.Engine
{
    public class ScannerCoordinator : IDisposable
    {
        public SignatureScanner SignatureEngine { get; } = new();
        public HeuristicPeAnalyzer HeuristicEngine { get; } = new();
        public SonarReputationEngine SonarEngine { get; } = new();
        public AdwareSpywareShield AdwareEngine { get; } = new();
        public AiThreatDefenseShield AiEngine { get; } = new();
        public ProcessBehaviorWatcher ProcessWatcher { get; } = new();
        public NetworkPortAuditor NetworkAuditor { get; } = new();
        public DeepPersistenceCleaner PersistenceCleaner { get; } = new();
        public QuarantineVault Vault { get; } = new();
        public RansomwareCanaryTrap CanaryTrap { get; }
        public RealtimeFileShield RealtimeShield { get; }

        private readonly object _stateLock = new();
        private readonly ScanState _state = new();
        private CancellationTokenSource? _scanCts;
        private Stopwatch _stopwatch = new();

        public ScannerCoordinator()
        {
            CanaryTrap = new RansomwareCanaryTrap(threat =>
            {
                AddThreat(threat);
                Log($"🚨 CANARY TUZAĞI TETİKLENDİ: {threat.Description}", "CRITICAL");
            });

            RealtimeShield = new RealtimeFileShield(
                filePath => ScanSingleFile(filePath),
                threat =>
                {
                    AddThreat(threat);
                    Log($"🛡️ Canlı Kalkan Tehdit Yakaladı: {threat.ThreatName} ({Path.GetFileName(threat.FilePath)})", "WARNING");
                }
            );

            Log("💎 SafirGuard Savunma Çekirdeği (.NET 8/10) Başlatıldı.", "SUCCESS");
            Log("🚀 Safir Sentinel İtibar, Sezgisel Entropi ve Yapay Zeka (AI) Kalkanları Devrede.", "INFO");
        }

        public void Log(string message, string level = "INFO")
        {
            lock (_stateLock)
            {
                _state.Logs.Add(new LogEntry { Message = message, Level = level });
                if (_state.Logs.Count > 250)
                {
                    _state.Logs.RemoveAt(0);
                }
            }
        }

        public ThreatItem? ScanSingleFile(string filePath)
        {
            if (!File.Exists(filePath)) return null;

            // 1. Safir LNK Kontrolü
            if (filePath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
            {
                var lnkThreat = AdwareEngine.ScanLnkShortcut(filePath);
                if (lnkThreat != null) return lnkThreat;
            }

            // 2. İmza & Hash Taraması (EICAR & Bilinen Tehditler)
            var sigThreat = SignatureEngine.ScanFile(filePath);
            if (sigThreat != null) return sigThreat;

            // 3. Yapay Zeka Saldırı & Model Güvenlik Kalkanı (AI Prompt Injection & Malicious Pickle Models)
            var aiThreat = AiEngine.ScanAiThreats(filePath);
            if (aiThreat != null) return aiThreat;

            // 4. Safir SpyGuard Web & Spyware Kalıpları
            var adThreat = AdwareEngine.ScanAdwareContent(filePath);
            if (adThreat != null) return adThreat;

            // 5. Safir PE & Entropi Sezgisel Taraması
            var heurThreat = HeuristicEngine.ScanPeFile(filePath);
            if (heurThreat != null) return heurThreat;

            // 6. Safir Sentinel Çok Faktörlü İtibar Taraması
            var sonarThreat = SonarEngine.AnalyzeFileReputation(filePath);
            if (sonarThreat != null) return sonarThreat;

            return null;
        }

        public bool StartScan(string scanType = "quick", string customPath = "")
        {
            lock (_stateLock)
            {
                if (_state.IsScanning) return false;

                _state.IsScanning = true;
                _state.ScanType = char.ToUpper(scanType[0]) + scanType.Substring(1);
                _state.Progress = 0;
                _state.ScannedFiles = 0;
                _state.Threats.Clear();
                _state.CurrentTarget = "Dosyalar taranıyor...";
                _scanCts = new CancellationTokenSource();
                _stopwatch = Stopwatch.StartNew();
            }

            Task.Run(() => RunScanWorker(scanType, customPath, _scanCts.Token));
            return true;
        }

        public void StopScan()
        {
            _scanCts?.Cancel();
            Log("Kullanıcı tarafından tarama durduruldu.", "WARNING");
        }

        private void RunScanWorker(string scanType, string customPath, CancellationToken token)
        {
            Log($"🔍 {scanType.ToUpper()} Taraması Başlatıldı...", "INFO");

            var targets = new List<string>();
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string desktop = Path.Combine(userProfile, "Desktop");
            string downloads = Path.Combine(userProfile, "Downloads");
            string tempDir = Path.GetTempPath();

            if (scanType.Equals("quick", StringComparison.OrdinalIgnoreCase))
            {
                targets.Add(desktop);
                targets.Add(downloads);

                // Süreçleri incele
                Log("⚡ Canlı süreçler inceleniyor (Safir System Watcher)...", "INFO");
                var procs = ProcessWatcher.ScanRunningProcesses();
                foreach (var p in procs)
                {
                    if (p.RiskLevel == "High" || p.RiskLevel == "Suspicious")
                    {
                        AddThreat(new ThreatItem
                        {
                            ThreatName = $"Safir.Proc.{p.Name}",
                            ThreatType = "Suspicious Process",
                            Severity = p.RiskLevel,
                            DetectionMethod = "Safir System Watcher",
                            FilePath = $"PID: {p.Pid} - {p.ExecutablePath}",
                            Pid = p.Pid,
                            Description = string.Join("; ", p.Reasons)
                        });
                    }
                }
            }
            else if (scanType.Equals("adware", StringComparison.OrdinalIgnoreCase))
            {
                Log("📢 Safir SpyGuard Modu: Kısayollar, Başlangıç ve PUP kayıtları taranıyor...", "INFO");
                targets.Add(desktop);
                targets.Add(downloads);

                // Başlangıç kayıtları
                var autoruns = PersistenceCleaner.ScanStartupEntries();
                foreach (var a in autoruns)
                {
                    if (a.RiskLevel == "High" || a.RiskLevel == "Suspicious")
                    {
                        AddThreat(new ThreatItem
                        {
                            ThreatName = $"Safir.Autorun.{a.Name}",
                            ThreatType = "Suspicious Startup Entry",
                            Severity = a.RiskLevel,
                            DetectionMethod = "Safir Power Eraser",
                            FilePath = a.Command,
                            Description = $"{a.Location} — {string.Join("; ", a.Reasons)}"
                        });
                    }
                }
            }
            else if (scanType.Equals("custom", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(customPath))
            {
                targets.Add(customPath);
            }
            else
            {
                targets.Add(desktop);
                targets.Add(downloads);
                targets.Add(tempDir);
            }

            // Dosyaları topla
            var fileList = new List<string>();
            foreach (var target in targets)
            {
                if (!Directory.Exists(target) && !File.Exists(target)) continue;

                if (File.Exists(target))
                {
                    fileList.Add(target);
                }
                else
                {
                    try
                    {
                        foreach (var f in Directory.EnumerateFiles(target, "*.*", SearchOption.AllDirectories))
                        {
                            if (f.Contains("quarantine_vault")) continue;
                            fileList.Add(f);
                            if (fileList.Count >= 2000 && scanType.Equals("quick", StringComparison.OrdinalIgnoreCase))
                                break;
                        }
                    }
                    catch { }
                }
            }

            int total = fileList.Count;
            Log($"Taranacak dosya sayısı: {total}", "INFO");

            for (int i = 0; i < total; i++)
            {
                if (token.IsCancellationRequested) break;

                string file = fileList[i];
                lock (_stateLock)
                {
                    _state.ScannedFiles = i + 1;
                    _state.Progress = total > 0 ? (int)(((i + 1) / (double)total) * 100) : 100;
                    _state.CurrentTarget = Path.GetFileName(file);
                    _state.ElapsedSeconds = Math.Round(_stopwatch.Elapsed.TotalSeconds, 1);
                }

                try
                {
                    var threat = ScanSingleFile(file);
                    if (threat != null)
                    {
                        AddThreat(threat);
                        Log($"⚠️ TEHDİT BULUNDU: {threat.ThreatName} ({Path.GetFileName(file)})", "WARNING");
                    }
                }
                catch { }

                Thread.Sleep(1);
            }

            lock (_stateLock)
            {
                _state.IsScanning = false;
                _state.Progress = 100;
                _state.CurrentTarget = "Tarama tamamlandı.";
                _state.ElapsedSeconds = Math.Round(_stopwatch.Elapsed.TotalSeconds, 1);
            }

            Log($"✅ Tarama Tamamlandı. {_state.ScannedFiles} dosya incelendi, {_state.ThreatsCount} tehdit tespit edildi.", "SUCCESS");
        }

        private void AddThreat(ThreatItem threat)
        {
            lock (_stateLock)
            {
                _state.Threats.Add(threat);
            }
        }

        public ScanState GetState()
        {
            lock (_stateLock)
            {
                if (_state.IsScanning)
                {
                    _state.ElapsedSeconds = Math.Round(_stopwatch.Elapsed.TotalSeconds, 1);
                }

                return new ScanState
                {
                    IsScanning = _state.IsScanning,
                    ScanType = _state.ScanType,
                    Progress = _state.Progress,
                    ScannedFiles = _state.ScannedFiles,
                    CurrentTarget = _state.CurrentTarget,
                    ElapsedSeconds = _state.ElapsedSeconds,
                    Threats = new List<ThreatItem>(_state.Threats),
                    Logs = new List<LogEntry>(_state.Logs)
                };
            }
        }

        public void Dispose()
        {
            CanaryTrap.Dispose();
            RealtimeShield.Dispose();
            _scanCts?.Dispose();
        }
    }
}
