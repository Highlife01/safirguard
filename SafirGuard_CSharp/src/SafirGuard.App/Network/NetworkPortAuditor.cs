using System;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using SafirGuard.App.Models;

namespace SafirGuard.App.Network
{
    /// <summary>
    /// Safir Akıllı Ağ ve Port Güvenlik Denetçisi
    /// </summary>
    public class NetworkPortAuditor
    {
        private static readonly HashSet<int> SuspiciousMiningPorts = new()
        {
            3333, 4444, 5555, 7777, 8888, 14444, 14433, 45560
        };

        public List<NetworkConnectionItem> ScanActiveConnections()
        {
            var results = new List<NetworkConnectionItem>();

            try
            {
                var ipProperties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = ipProperties.GetActiveTcpConnections();

                foreach (var conn in tcpConnections)
                {
                    string local = $"{conn.LocalEndPoint.Address}:{conn.LocalEndPoint.Port}";
                    string remote = $"{conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}";
                    string state = conn.State.ToString();

                    string risk = "Safe";
                    string reason = "Standart Ağ Bağlantısı";

                    if (SuspiciousMiningPorts.Contains(conn.RemoteEndPoint.Port))
                    {
                        risk = "High";
                        reason = $"Bilinen Kripto Madencilik / C2 Portuna Bağlantı (Port: {conn.RemoteEndPoint.Port})";
                    }

                    results.Add(new NetworkConnectionItem
                    {
                        LocalEndpoint = local,
                        RemoteEndpoint = remote,
                        State = state,
                        Protocol = "TCP",
                        RiskLevel = risk,
                        Reason = reason
                    });
                }
            }
            catch
            {
                // Ağ izinleri
            }

            return results;
        }
    }
}
