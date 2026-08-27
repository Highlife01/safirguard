using System;
using System.Collections.Generic;

namespace SafirGuard.App.Models
{
    public class ThreatItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string ThreatName { get; set; } = string.Empty;
        public string ThreatType { get; set; } = "Malware";
        public string Severity { get; set; } = "Medium"; // Low, Medium, High, Critical
        public string DetectionMethod { get; set; } = "Signature";
        public string FilePath { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string DetectedAt { get; set; } = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        public string Sha256 { get; set; } = string.Empty;
        public int? Pid { get; set; }
    }

    public class LogEntry
    {
        public string Time { get; set; } = DateTime.Now.ToString("HH:mm:ss");
        public string Level { get; set; } = "INFO"; // INFO, SUCCESS, WARNING, CRITICAL
        public string Message { get; set; } = string.Empty;
    }

    public class ScanState
    {
        public bool IsScanning { get; set; } = false;
        public string ScanType { get; set; } = "Idle";
        public int Progress { get; set; } = 0;
        public int ScannedFiles { get; set; } = 0;
        public int ThreatsCount => Threats.Count;
        public string CurrentTarget { get; set; } = "Hazır";
        public double ElapsedSeconds { get; set; } = 0;
        public List<ThreatItem> Threats { get; set; } = new();
        public List<LogEntry> Logs { get; set; } = new();
    }

    public class QuarantineItem
    {
        public string Id { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string OriginalPath { get; set; } = string.Empty;
        public string ThreatName { get; set; } = string.Empty;
        public string ThreatType { get; set; } = string.Empty;
        public string QuarantinedAt { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public string Sha256 { get; set; } = string.Empty;
        public string VaultFile { get; set; } = string.Empty;
    }

    public class AutorunItem
    {
        public string Name { get; set; } = string.Empty;
        public string Command { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public string SourceType { get; set; } = "Registry";
        public string RiskLevel { get; set; } = "Safe"; // Safe, Suspicious, High
        public List<string> Reasons { get; set; } = new();
    }

    public class ProcessItem
    {
        public int Pid { get; set; }
        public string Name { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
        public double MemoryMb { get; set; }
        public string RiskLevel { get; set; } = "Safe";
        public List<string> Reasons { get; set; } = new();
    }

    public class NetworkConnectionItem
    {
        public string LocalEndpoint { get; set; } = string.Empty;
        public string RemoteEndpoint { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public string Protocol { get; set; } = "TCP";
        public string RiskLevel { get; set; } = "Safe";
        public string Reason { get; set; } = string.Empty;
    }

    public class CanaryTrapStatus
    {
        public bool IsActive { get; set; } = true;
        public int TotalTraps { get; set; } = 0;
        public int TriggeredAlerts { get; set; } = 0;
        public List<string> TrapPaths { get; set; } = new();
    }

    public class SystemStatusResponse
    {
        public string Status { get; set; } = "online";
        public ScanState Scanner { get; set; } = new();
        public bool RealtimeShieldActive { get; set; } = true;
        public CanaryTrapStatus CanaryTrap { get; set; } = new();
        public int QuarantineCount { get; set; } = 0;
        public string Timestamp { get; set; } = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    }
}
