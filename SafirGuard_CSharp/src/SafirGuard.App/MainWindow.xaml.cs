using System;
using System.IO;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace SafirGuard.App
{
    public partial class MainWindow : Window
    {
        private readonly int _serverPort;

        public MainWindow(int serverPort)
        {
            InitializeComponent();
            _serverPort = serverPort;
            Loaded += MainWindow_Loaded;
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                string userDataFolder = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "SafirGuard", "WebView2Data");

                Directory.CreateDirectory(userDataFolder);
                var env = await CoreWebView2Environment.CreateAsync(null, userDataFolder);
                await CyberWebView.EnsureCoreWebView2Async(env);

                CyberWebView.CoreWebView2.Settings.IsStatusBarEnabled = false;
                CyberWebView.CoreWebView2.Settings.AreDevToolsEnabled = false;
                CyberWebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = true;

                // Localhost Kestrel adresine yönlendir
                CyberWebView.Source = new Uri($"http://127.0.0.1:{_serverPort}");

                CyberWebView.NavigationCompleted += (s, args) =>
                {
                    LoadingOverlay.Visibility = Visibility.Collapsed;
                };
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"SafirGuard arayüzü yüklenirken bir sorun oluştu:\n{ex.Message}", 
                    "SafirGuard Güvenlik Paketi", 
                    MessageBoxButton.OK, 
                    MessageBoxImage.Error);
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            Application.Current.Shutdown();
        }
    }
}
