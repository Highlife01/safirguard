using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Collections.Generic;
using SafirGuard.App.Models;

namespace SafirGuard.App.Quarantine
{
    /// <summary>
    /// Safir Karantina Kasası — Tehditleri Şifreli Olarak İzole Eder
    /// </summary>
    public class QuarantineVault
    {
        private readonly string _vaultDir;
        private readonly string _metaFile;
        private const byte XorKey = 0x5A;
        private readonly object _lock = new();

        public QuarantineVault(string? vaultDir = null)
        {
            _vaultDir = vaultDir ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "quarantine_vault");
            _metaFile = Path.Combine(_vaultDir, "quarantine_manifest.json");
            EnsureVault();
        }

        private void EnsureVault()
        {
            if (!Directory.Exists(_vaultDir))
            {
                Directory.CreateDirectory(_vaultDir);
            }
            if (!File.Exists(_metaFile))
            {
                SaveManifest(new Dictionary<string, QuarantineItem>());
            }
        }

        private Dictionary<string, QuarantineItem> LoadManifest()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_metaFile))
                    {
                        string json = File.ReadAllText(_metaFile);
                        return JsonSerializer.Deserialize<Dictionary<string, QuarantineItem>>(json) ?? new();
                    }
                }
                catch { }
                return new();
            }
        }

        private void SaveManifest(Dictionary<string, QuarantineItem> manifest)
        {
            lock (_lock)
            {
                string json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_metaFile, json);
            }
        }

        private byte[] XorTransform(byte[] data)
        {
            byte[] output = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                output[i] = (byte)(data[i] ^ XorKey);
            }
            return output;
        }

        public QuarantineItem? QuarantineFile(string filePath, string threatName, string threatType = "Malware")
        {
            if (!File.Exists(filePath)) return null;

            try
            {
                byte[] rawBytes = File.ReadAllBytes(filePath);
                string sha256 = Convert.ToHexString(SHA256.HashData(rawBytes)).ToLowerInvariant();
                string fileName = Path.GetFileName(filePath);
                string qId = $"Q_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}_{sha256.Substring(0, 8)}";
                string vaultFileName = $"{qId}.safir_locked";
                string vaultFilePath = Path.Combine(_vaultDir, vaultFileName);

                // XOR şifreleme ve kasaya yazma
                byte[] lockedBytes = XorTransform(rawBytes);
                File.WriteAllBytes(vaultFilePath, lockedBytes);

                // Orijinal dosyayı sil
                try
                {
                    File.Delete(filePath);
                }
                catch { }

                var item = new QuarantineItem
                {
                    Id = qId,
                    FileName = fileName,
                    OriginalPath = Path.GetFullPath(filePath),
                    ThreatName = threatName,
                    ThreatType = threatType,
                    QuarantinedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                    FileSize = rawBytes.Length,
                    Sha256 = sha256,
                    VaultFile = vaultFileName
                };

                var manifest = LoadManifest();
                manifest[qId] = item;
                SaveManifest(manifest);

                return item;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[QuarantineVault Error] {ex.Message}");
                return null;
            }
        }

        public bool RestoreFile(string qId)
        {
            var manifest = LoadManifest();
            if (!manifest.TryGetValue(qId, out var item)) return false;

            string vaultFilePath = Path.Combine(_vaultDir, item.VaultFile);
            if (!File.Exists(vaultFilePath)) return false;

            try
            {
                byte[] lockedBytes = File.ReadAllBytes(vaultFilePath);
                byte[] origBytes = XorTransform(lockedBytes);

                string? origDir = Path.GetDirectoryName(item.OriginalPath);
                if (!string.IsNullOrEmpty(origDir) && !Directory.Exists(origDir))
                {
                    Directory.CreateDirectory(origDir);
                }

                File.WriteAllBytes(item.OriginalPath, origBytes);
                File.Delete(vaultFilePath);

                manifest.Remove(qId);
                SaveManifest(manifest);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool DeletePermanently(string qId)
        {
            var manifest = LoadManifest();
            if (!manifest.TryGetValue(qId, out var item)) return false;

            string vaultFilePath = Path.Combine(_vaultDir, item.VaultFile);
            if (File.Exists(vaultFilePath))
            {
                try
                {
                    // Güvenli silme: dosyanın üzerine sıfır yaz
                    long len = new FileInfo(vaultFilePath).Length;
                    File.WriteAllBytes(vaultFilePath, new byte[len]);
                    File.Delete(vaultFilePath);
                }
                catch { }
            }

            manifest.Remove(qId);
            SaveManifest(manifest);
            return true;
        }

        public List<QuarantineItem> ListQuarantined()
        {
            return new List<QuarantineItem>(LoadManifest().Values);
        }
    }
}
