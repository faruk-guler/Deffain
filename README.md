# Deffain OpenSource Firewall

Deffain, Linux sunucularda nftables kullanarak firewall yönetimini çok basit komutlarla yapmanızı sağlayan açık kaynak bir güvenlik çözümüdür.

## Özellikler

- Basit ve anlaşılır komut yapısı
- Modern nftables altyapısı
- Yüksek performans
- Düşük kaynak kullanımı
- IPv4 ve IPv6 desteği
- IP ve port bazlı filtreleme
- Kolay kurulum ve yönetim

## Kurulum

1. nftables'ı yükleyin (eğer yüklü değilse):
```bash
sudo apt-get update
sudo apt-get install nftables
```

2. Deffain'i çalıştırılabilir yapın:
```bash
chmod +x deffain.py
```

## Kullanım

Deffain'i kullanmak için komutları tırnak içinde yazın:

```bash
sudo ./deffain.py 'komut'
```

### Örnek Komutlar

1. Port açma/kapama:
```bash
sudo ./deffain.py 'port open 22'     # 22 portunu herkese aç
sudo ./deffain.py 'port close 22'    # 22 portunu herkese kapat
```

2. IP bazlı port yönetimi:
```bash
sudo ./deffain.py 'port open 22 > 1.2.3.4'  # 22 portunu sadece 1.2.3.4 IP'sine aç
sudo ./deffain.py 'port open 22 < 1.2.3.4'  # 1.2.3.4 IP'sinden gelen 22 portuna izin ver
```

3. Firewall kontrolü:
```bash
sudo ./deffain.py 'status'  # Firewall durumunu göster
sudo ./deffain.py 'on'      # Firewall'u aç
sudo ./deffain.py 'off'     # Firewall'u kapat
```

4. Yardım:
```bash
sudo ./deffain.py 'help'    # Tüm komutları göster
```

## Komut Açıklamaları

- `port open 22` -> 22 portunu herkese açar
- `port close 22` -> 22 portunu herkese kapatır
- `port open 22 > 1.2.3.4` -> 22 portunu sadece 1.2.3.4 IP'sine açar
- `port open 22 < 1.2.3.4` -> 1.2.3.4 IP'sinden gelen 22 portuna izin verir
- `port close 22 > 1.2.3.4` -> 22 portunu 1.2.3.4 IP'sine kapatır
- `port close 22 < 1.2.3.4` -> 1.2.3.4 IP'sinden gelen 22 portunu engeller
- `status` -> Firewall durumunu gösterir
- `on` -> Firewall'u açar
- `off` -> Firewall'u kapatır
- `help` -> Tüm komutları gösterir

## Güvenlik Notları

1. Deffain her zaman root yetkisiyle çalıştırılmalıdır
2. Firewall'u açmadan önce SSH erişiminizi kaybetmemek için SSH portuna (22) izin verdiğinizden emin olun
3. Kritik servislerin portlarını engellememeye dikkat edin
4. Değişiklikleri test etmeden production ortamında uygulamayın

## nftables Avantajları

1. Modern ve daha esnek bir yapı
2. Daha iyi performans
3. Daha az bellek kullanımı
4. Daha iyi hata ayıklama özellikleri
5. IPv4 ve IPv6 desteği tek komutla

## Katkıda Bulunma

Deffain açık kaynak bir projedir. Katkıda bulunmak için:

1. Bu repository'yi fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/yeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik: Açıklama'`)
4. Branch'inizi push edin (`git push origin feature/yeniOzellik`)
5. Pull Request oluşturun

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın. 