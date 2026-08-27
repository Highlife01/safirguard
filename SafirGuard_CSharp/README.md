# 💎 SafirGuard — Next-Gen Antivirus, Anti-Spyware & AI Threat Defense Suite

<div align="center">

![SafirGuard Cyber Shield](https://img.shields.io/badge/SAFIRGUARD-v1.0.0--PRO-00f2fe?style=for-the-badge&logo=shield&logoColor=black)
![.NET 8 / 10](https://img.shields.io/badge/.NET-8.0%20%7C%2010.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![Build Passing](https://img.shields.io/badge/Build-Passing-2ed573?style=for-the-badge&logo=githubactions&logoColor=white)
![License MIT](https://img.shields.io/badge/License-MIT-ff4757?style=for-the-badge)
![AI Defense](https://img.shields.io/badge/AI--Shield-Prompt%20%26%20Model%20RCE%20Protected-a855f7?style=for-the-badge&logo=openai&logoColor=white)

<p align="center">
  <b>En gelişmiş siber güvenlik teknolojilerini Yapay Zeka (AI) Savunma Kalkanı ile birleştiren C# tabanlı açık kaynaklı yeni nesil antivirüs paketi.</b>
</p>

[✨ Özellikler](#-öne-çıkan-özellikler) •
[🤖 Yapay Zeka Savunması](#-yapay-zeka-ai-saldırı-kalkanı) •
[🏛️ Mimari](#️-mimari-ve-savunma-katmanları) •
[🚀 Hızlı Başlangıç](#-hızlı-başlangıç) •
[📦 Bağımsız EXE](#-bağımsız-exe-çalıştırma) •
[📜 Lisans](#-lisans)

</div>

---

## 🌟 Öne Çıkan Özellikler

```
========================================================================================================
💎 SAFIRGUARD DÜNYA STANDARTLARINDA GÜVENLİK MATRİSİ
========================================================================================================
  [✓] Safir Heuristic PE & Shannon Entropy Analyzer (UPX / Themida / VMP Obfuscation Tespiti)
  [✓] Safir System Watcher (Gizli Süreçler, Sahte svch0st.exe, Bellek Enjeksiyonu İzleme)
  [✓] Safir Anti-Ransomware Canary Trap (Masaüstü ve Belgelerde Nöbetçi Yem Dosyalar ile Anında Kilitleme)
  [✓] Safir Zero-Day Real-Time I/O Shield (Çok İş Parçacıklı Anlık Dosya Sistemi Kalkanı)
  [✓] Safir Sentinel Multi-Factor Reputation Engine (Çift Uzantı .pdf.exe ve Gölge Kopya İmha Engeli)
  [✓] Safir Power Eraser & Deep Persistence Cleaner (Windows Registry Run & Startup Kalıntı Temizliği)
  [✓] Safir SpyGuard & Browser Hijacker Shield (LNK Kısayol Yönlendirme & Web Miner Tespiti)
  [✓] 🤖 Safir AI Threat Shield (Prompt Injection, Jailbreak, Pickle RCE & Polimorfik Kod Tespiti)
  [✓] Safir Encrypted Vault (Byte-Maskelemeli .safir_locked Güvenli Karantina Kasası)
========================================================================================================
```

---

## 🤖 Yapay Zeka (AI) Saldırı Kalkanı

SafirGuard, yalnızca geleneksel zararlıları değil; **yapay zeka çağının yeni nesil tehditlerini** de etkisiz hale getirir:

1. **Prompt Injection & LLM Jailbreak Kalkanı**:
   - `Ignore previous instructions`, `DAN mode`, `Developer mode` gibi yerel veya bulut tabanlı yapay zeka ajanlarını manipüle etmeye yönelik komutları engeller.
   - Görünmez Unicode (`Zero-Width Characters`) hilelerini tespit eder.
2. **Güvensiz Yapay Zeka Modelleri & Pickle RCE Tespiti**:
   - PyTorch (`.pt`, `.bin`), ONNX ve Pickle model dosyaları içine gizlenmiş `os.system`, `subprocess.Popen`, `eval` kancalarını tespit ederek uzaktan kod yürütülmesini önler.
3. **Yapay Zeka Üretimi Polimorfik Kod Analizi**:
   - LLM'ler tarafından dinamik üretilmiş değişken kabuk kodlarını sezgisel yakalar.

---

## 🏛️ Mimari ve Savunma Katmanları

```mermaid
graph TD
    UI[💎 SafirGuard Neon Cyber Desktop Dashboard] --> Core[⚙️ SafirGuard Core (.NET 8/10)]
    
    subgraph "Safir Sezgisel Katmanı"
        Core --> KaspHeur[🔍 PE Başlık & Shannon Entropi Motoru]
        Core --> KaspWatcher[⚡ System Watcher & Süreç Davranış Monitörü]
        Core --> KaspNet[🌐 Akıllı Ağ Soket & Port Denetleyicisi]
    end
    
    subgraph "Safir Koruma Katmanı"
        Core --> BitCanary[🪤 Ransomware Canary Yem Tuzağı]
        Core --> BitShield[🛡️ Real-Time I/O Çok İş Parçacıklı Kalkan]
    end
    
    subgraph "Safir Sentinel Katmanı"
        Core --> NortSonar[🎯 Sentinel Çok Faktörlü İtibar Motoru]
        Core --> NortEraser[🧹 Power Eraser: Registry & Startup Temizliği]
    end
    
    subgraph "Safir SpyGuard & AI Katmanı"
        Core --> AdHijack[📢 Browser Hijacker & LNK Kısayol Denetimi]
        Core --> AiShield[🤖 AI Prompt Injection & Model RCE Shield]
    end
    
    subgraph "Güvenli İzolasyon"
        Core --> Vault[🔒 Safir Şifreli Karantina Kasası]
    end
```

---

## 🚀 Hızlı Başlangıç

### Gereksinimler
- Windows 10 / 11 (x64)
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) veya üzeri

### Projeyi Çalıştırma

```powershell
# Depoyu klonlayın
git clone https://github.com/your-username/safirguard-antivirus.git
cd safirguard-antivirus

# Testleri çalıştırın
dotnet test

# Uygulamayı başlatın
dotnet run --project src/SafirGuard.App
```

---

## 📦 Bağımsız EXE Çalıştırma

SafirGuard, .NET kurulumuna ihtiyaç duymadan **tek bir bağımsız `.exe` dosyası** olarak derlenebilir:

```powershell
dotnet publish src/SafirGuard.App/SafirGuard.App.csproj -c Release -r win-x64 --self-contained false -o publish/
```

Derlenen `publish/SafirGuard.App.exe` dosyasını çift tıklayarak anında çalıştırabilirsiniz!

---

## 🧪 Birim Testleri

```
Toplam 7 Test Çalıştırıldı:
  [✓] Test01: İmza ve Hash Eşleştirme Motoru
  [✓] Test02: Safir PE Shannon Entropi Hesaplama
  [✓] Test03: Safir Sentinel Çift Uzantı (.pdf.exe) Engelleme
  [✓] Test04: Safir SpyGuard Reklam Enjektör ve Takip Tespiti
  [✓] Test05: Safir Karantina Kasası İzolasyon ve Geri Yükleme
  [✓] Test06: Yapay Zeka Prompt Injection & Jailbreak Tespiti
  [✓] Test07: Yapay Zeka Pickle RCE Model Güvenlik Tespiti

Sonuç: %100 Başarı (0 Hata)
```

---

## 👨‍💻 Geliştirici & İletişim

* **Geliştirici**: Cebrail Kara
* **Web Sitesi**: [www.safirsuite.com.tr](https://www.safirsuite.com.tr)
* **E-Posta**: [info@safirsuite.com.tr](mailto:info@safirsuite.com.tr) • [info@benimyaverim.com.tr](mailto:info@benimyaverim.com.tr)
* **Ekosistem**: SafirSuite & Benim Yaverim Yazılım Teknolojileri

---

## 📜 Lisans

Bu proje [MIT Lisansı](LICENSE) kapsamında açık kaynak olarak yayınlanmıştır.
© 2026 Cebrail Kara — SafirSuite. Tüm hakları saklıdır.
