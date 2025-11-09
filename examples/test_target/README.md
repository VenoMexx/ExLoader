# ExLoader Test Target Application

Bu uygulama, ExLoader'ın tüm hook modüllerini test etmek için tasarlanmış bir demo uygulamasıdır.

## Özellikler

### Network API'leri
- **WinHTTP**: GET ve POST istekleri
- **WinInet**: GET ve POST istekleri
- **Winsock**: Raw TCP bağlantıları
- **URLMon**: Dosya indirme
- **Proxy API**: Proxy ayarları sorgulama

### Crypto API'leri
- **BCrypt/CNG**: AES-256 şifreleme/deşifreleme
- **CryptoAPI**: AES-256 şifreleme/deşifreleme
- **BCrypt Hash**: SHA-256 hesaplama

## Derleme

```bash
# ExLoader ana dizininden
cd examples/test_target
mkdir build
cd build
cmake .. -G "MinGW Makefiles"
cmake --build .
```

## Kullanım

### 1. Normal Çalıştırma
```bash
./test_target.exe
```

### 2. ExLoader ile İzleme
```bash
# ExLoader'ı başlatın
../../exloader.exe --target test_target.exe --profile ../../profiles/templates/default.json --log test_run.jsonl
```

### 3. Attach Mode
```bash
# Önce test_target'ı başlatın
./test_target.exe

# Başka bir terminalde, PID'yi bulup attach edin
../../exloader.exe --pid <PID> --attach --profile ../../profiles/templates/default.json --log attach_run.jsonl
```

## Test Senaryoları

### Senaryo 1: Kullanıcı Kimlik Doğrulama
1. httpbin.org'dan JSON verisi çeker (WinHTTP GET)
2. Veriyi BCrypt ile şifreler (AES-256)
3. Şifreyi çözer ve doğrular

### Senaryo 2: Şifreli Veri Gönderimi
1. Kullanıcı verisi hazırlar
2. CryptoAPI ile şifreler
3. WinInet POST ile gönderir

### Senaryo 3: Güvenli Dosya İndirme
1. URLMon ile dosya indirir
2. BCrypt ile SHA-256 hash hesaplar

### Senaryo 4: Çoklu API Kullanımı
1. WinHTTP GET
2. WinInet GET
3. Winsock bağlantı testi
4. Proxy ayarları kontrolü

### Senaryo 5: Saf Kripto İşlemleri
1. Hassas veriyi BCrypt ile şifreler/deşifreler
2. Aynı veriyi CryptoAPI ile işler
3. Hash hesaplar

## Beklenen Hook Çıktısı

ExLoader bu uygulamayı izlerken şu tür olayları yakalamalıdır:

```jsonl
{"type":"network.request","api":"WinHttpSendRequest","url":"https://httpbin.org/json",...}
{"type":"network.response","api":"WinHttpReceiveResponse","status":200,...}
{"type":"crypto.key","api":"BCryptGenerateSymmetricKey","algorithm":"AES",...}
{"type":"crypto.encrypt","api":"BCryptEncrypt","key_size":256,...}
{"type":"crypto.decrypt","api":"BCryptDecrypt",...}
{"type":"network.request","api":"HttpSendRequestA","url":"https://httpbin.org/post",...}
{"type":"crypto.hash","api":"BCryptHashData","algorithm":"SHA256",...}
```

## Sorun Giderme

### Bağlantı Hataları
- İnternet bağlantınızı kontrol edin
- Firewall ayarlarını kontrol edin
- httpbin.org erişilebilir mi test edin

### Derleme Hataları
- MinGW-w64 kurulu mu?
- Windows SDK kurulu mu?
- CMake 3.22+ sürümü mü?

## Notlar

- Uygulama gerçek kullanıcı verisi içermez, sadece demo amaçlıdır
- Tüm HTTP istekleri httpbin.org test API'sine gider
- Kripto anahtarları sabit kodludur (üretim kullanımı için uygun değil)
- Sleep delay'leri log okunabilirliği içindir
