using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using SafirGuard.App.Engine;
using SafirGuard.App.Models;

namespace SafirGuard.App.Engine
{
    public static class WebServerHost
    {
        public static (WebApplication app, int port) BuildAndStart()
        {
            // Dinamik Port Tespiti (Port 8788 doluysa otomatik sonraki porta geçer)
            int port = 8788;
            for (int p = 8788; p <= 8800; p++)
            {
                try
                {
                    var listener = new TcpListener(IPAddress.Loopback, p);
                    listener.Start();
                    listener.Stop();
                    port = p;
                    break;
                }
                catch { }
            }

            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                Args = Array.Empty<string>()
            });

            builder.WebHost.UseUrls($"http://127.0.0.1:{port}");

            // Singleton Coordinator
            builder.Services.AddSingleton<ScannerCoordinator>();

            // Gömülü (Embedded) wwwroot File Provider Yapılandırması
            IFileProvider fileProvider;
            try
            {
                var embeddedProvider = new ManifestEmbeddedFileProvider(Assembly.GetExecutingAssembly(), "wwwroot");
                string physicalWebRoot = Path.Combine(builder.Environment.ContentRootPath, "wwwroot");
                if (Directory.Exists(physicalWebRoot))
                {
                    fileProvider = new CompositeFileProvider(new PhysicalFileProvider(physicalWebRoot), embeddedProvider);
                }
                else
                {
                    fileProvider = embeddedProvider;
                }
            }
            catch
            {
                fileProvider = builder.Environment.WebRootFileProvider;
            }

            builder.Environment.WebRootFileProvider = fileProvider;

            var app = builder.Build();

            app.UseDefaultFiles(new DefaultFilesOptions
            {
                FileProvider = fileProvider
            });

            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = fileProvider
            });

            app.MapFallbackToFile("index.html", new StaticFileOptions
            {
                FileProvider = fileProvider
            });

            // --- API ENDPOINTS ---

            app.MapGet("/api/status", (ScannerCoordinator coordinator) =>
            {
                var scanState = coordinator.GetState();
                var canaryStatus = coordinator.CanaryTrap.GetStatus();
                var quarantined = coordinator.Vault.ListQuarantined();

                return Results.Ok(new SystemStatusResponse
                {
                    Status = "online",
                    Scanner = scanState,
                    RealtimeShieldActive = coordinator.RealtimeShield.IsActive,
                    CanaryTrap = canaryStatus,
                    QuarantineCount = quarantined.Count,
                    Timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
                });
            });

            app.MapPost("/api/scan/start", (ScanRequest req, ScannerCoordinator coordinator) =>
            {
                bool success = coordinator.StartScan(req.Type ?? "quick", req.CustomPath ?? "");
                if (!success)
                {
                    return Results.BadRequest(new { status = "error", message = "Zaten devam eden bir tarama mevcut." });
                }
                return Results.Ok(new { status = "success", message = $"{req.Type} taraması başlatıldı." });
            });

            app.MapPost("/api/scan/stop", (ScannerCoordinator coordinator) =>
            {
                coordinator.StopScan();
                return Results.Ok(new { status = "success", message = "Tarama durdurma sinyali gönderildi." });
            });

            app.MapGet("/api/quarantine/list", (ScannerCoordinator coordinator) =>
            {
                var items = coordinator.Vault.ListQuarantined();
                return Results.Ok(new { items });
            });

            app.MapPost("/api/quarantine/action", (QuarantineActionRequest req, ScannerCoordinator coordinator) =>
            {
                if (req.Action == "quarantine" && !string.IsNullOrEmpty(req.FilePath))
                {
                    var entry = coordinator.Vault.QuarantineFile(req.FilePath, req.ThreatName ?? "Detected Threat", req.ThreatType ?? "Malware");
                    if (entry != null)
                    {
                        coordinator.Log($"🔒 Dosya Karantina Kasasına Kilitlendi: {req.FilePath}", "SUCCESS");
                        return Results.Ok(new { status = "success", entry });
                    }
                    return Results.Problem("Dosya karantinaya alınamadı.");
                }
                else if (req.Action == "restore" && !string.IsNullOrEmpty(req.Id))
                {
                    bool ok = coordinator.Vault.RestoreFile(req.Id);
                    if (ok)
                    {
                        coordinator.Log($"🔓 Dosya karantinadan geri yüklendi (ID: {req.Id})", "INFO");
                        return Results.Ok(new { status = "success" });
                    }
                    return Results.Problem("Geri yükleme başarısız.");
                }
                else if (req.Action == "delete" && !string.IsNullOrEmpty(req.Id))
                {
                    bool ok = coordinator.Vault.DeletePermanently(req.Id);
                    if (ok)
                    {
                        coordinator.Log($"🗑️ Karantinadaki dosya kalıcı olarak imha edildi (ID: {req.Id})", "WARNING");
                        return Results.Ok(new { status = "success" });
                    }
                    return Results.Problem("Silme işlemi başarısız.");
                }

                return Results.BadRequest(new { status = "error", message = "Geçersiz işlem parametresi." });
            });

            app.MapGet("/api/autoruns", (ScannerCoordinator coordinator) =>
            {
                var entries = coordinator.PersistenceCleaner.ScanStartupEntries();
                return Results.Ok(new { entries });
            });

            app.MapGet("/api/processes", (ScannerCoordinator coordinator) =>
            {
                var procs = coordinator.ProcessWatcher.ScanRunningProcesses();
                return Results.Ok(new { processes = procs });
            });

            app.MapPost("/api/process/kill", (ProcessKillRequest req, ScannerCoordinator coordinator) =>
            {
                bool ok = coordinator.ProcessWatcher.KillProcess(req.Pid);
                if (ok)
                {
                    coordinator.Log($"🛑 Süreç Sonlandırıldı (PID: {req.Pid})", "WARNING");
                    return Results.Ok(new { status = "success", message = $"PID {req.Pid} başarıyla sonlandırıldı." });
                }
                return Results.Problem("Süreç sonlandırılamadı.");
            });

            app.MapGet("/api/network", (ScannerCoordinator coordinator) =>
            {
                var conns = coordinator.NetworkAuditor.ScanActiveConnections();
                return Results.Ok(new { connections = conns });
            });

            app.MapPost("/api/ai/test-prompt", (AiTestRequest req, ScannerCoordinator coordinator) =>
            {
                if (string.IsNullOrWhiteSpace(req.Prompt))
                {
                    return Results.BadRequest(new { status = "error", message = "Prompt metni boş olamaz." });
                }

                string tempFile = Path.Combine(Path.GetTempPath(), "safir_ai_eval_" + Guid.NewGuid().ToString("N") + ".txt");
                try
                {
                    File.WriteAllText(tempFile, req.Prompt);
                    var threat = coordinator.AiEngine.ScanAiThreats(tempFile);
                    if (threat != null)
                    {
                        return Results.Ok(new
                        {
                            isSafe = false,
                            threatName = threat.ThreatName,
                            threatType = threat.ThreatType,
                            severity = threat.Severity,
                            description = threat.Description
                        });
                    }

                    return Results.Ok(new
                    {
                        isSafe = true,
                        message = "Temiz: Herhangi bir Prompt Injection, Jailbreak veya görünmez karakter anomalisi bulunamadı."
                    });
                }
                finally
                {
                    try { File.Delete(tempFile); } catch { }
                }
            });

            app.MapPost("/api/shield/toggle", (ShieldToggleRequest req, ScannerCoordinator coordinator) =>
            {
                if (req.Enable)
                {
                    coordinator.RealtimeShield.Start();
                    coordinator.Log("🛡️ Safir Canlı Kalkan ETKİNLEŞTİRİLDİ.", "SUCCESS");
                }
                else
                {
                    coordinator.RealtimeShield.Stop();
                    coordinator.Log("⚠️ Safir Canlı Kalkan DEVRE DIŞI BIRAKILDI.", "WARNING");
                }
                return Results.Ok(new { status = "success", isActive = coordinator.RealtimeShield.IsActive });
            });

            // Asenkron olarak arka planda Kestrel'i başlat
            _ = Task.Run(async () =>
            {
                try
                {
                    await app.StartAsync();
                }
                catch { }
            });

            return (app, port);
        }
    }

    public record ScanRequest(string? Type, string? CustomPath);
    public record QuarantineActionRequest(string Action, string? Id, string? FilePath, string? ThreatName, string? ThreatType);
    public record ProcessKillRequest(int Pid);
    public record ShieldToggleRequest(bool Enable);
    public record AiTestRequest(string Prompt);
}
