using System;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.AspNetCore.Builder;
using SafirGuard.App.Engine;

namespace SafirGuard.App
{
    public partial class App : Application
    {
        private WebApplication? _webHost;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            try
            {
                // Kestrel API ve güvenlik motorunu arka planda başlat
                var (host, port) = WebServerHost.BuildAndStart();
                _webHost = host;

                // Bağımsız Yerel Masaüstü Penceresini Aç
                var mainWindow = new MainWindow(port);
                mainWindow.Show();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"SafirGuard başlatılamadı:\n{ex.Message}", 
                    "SafirGuard Başlatma Hatası", 
                    MessageBoxButton.OK, 
                    MessageBoxImage.Error);
                Shutdown();
            }
        }

        protected override async void OnExit(ExitEventArgs e)
        {
            if (_webHost != null)
            {
                try
                {
                    await _webHost.StopAsync();
                    await _webHost.DisposeAsync();
                }
                catch { }
            }
            base.OnExit(e);
        }
    }
}
