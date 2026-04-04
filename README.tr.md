# Gerçek Zamanlı Erişim Uyarı Sistemi (RAAS)

[![CI](https://github.com/cumakurt/raas/actions/workflows/ci.yml/badge.svg)](https://github.com/cumakurt/raas/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**RAAS** (İngilizce adı: **Real-Time Access Alert System**) — dağıtımın kimlik doğrulama **dosyasını** (`auth.log` / `secure`) veya **systemd günlüğünü** (`journalctl`) izleyen, SSH/sudo/su ve diğer olayları ayrıştıran, risk skoru veren ve isteğe bağlı olarak **Telegram** üzerinden uyarı gönderen hafif bir Python aracıdır. YAML üzerinden skor ve eşikleri özelleştirebilir, güvenilen kaynak IP/CIDR’ları yok sayabilir ve izleme için küçük bir **HTTP health** JSON uç noktası açabilirsiniz.

**Sistem paketleri (DBus, ekran yakalama, ffmpeg, dağıtıma göre):** [DEPENDENCIES.tr.md](DEPENDENCIES.tr.md) · [DEPENDENCIES.md](DEPENDENCIES.md) (İngilizce)

**Katkı:** [CONTRIBUTING.md](CONTRIBUTING.md) · **Güvenlik:** [SECURITY.md](SECURITY.md)

## Linux uyumluluğu

- **Günlük yolu:** `log.backend` **`file`** iken (varsayılan) `log.path: auto` önerilir; `/var/log/auth.log` (Debian/Ubuntu/Kali) ve `/var/log/secure` (RHEL/Fedora/Alma/Rocky) sırayla denenir.
- **Journal modu:** `log.backend: journal` ile **`journalctl`** akışı kullanılır (`journalctl` yolunda olmalı, yani systemd). İsteğe bağlı `log.journal.journalctl_args` ile süzgeç eklenebilir (ör. `SYSLOG_FACILITY=10`).
- **Yapılandırma:** `--config` verilmezse `/opt/raas/config/config.yaml` (tipik kurulum) dosyası varsa o kullanılır; yoksa geliştirme düzeni olarak `config/config.yaml` (paketin yanında) kullanılır.
- **Ekran kilidi:** `loginctl` (systemd) ile kilit algısı; systemd yoksa ilgili özellik atlanır.
- **Servis kurulumu:** `install.sh` **systemd** gerektirir.

## Gereksinimler

### Temel

- Python **3.10+**
- **`file`** modunda kimlik doğrulama günlük dosyasına okuma (çoğu zaman **`adm`** grubu veya `sudo`; systemd servisi **root** olarak çalışır); **`journal`** modunda çalışan **journald** / `journalctl`
- **`install.sh`** ve `loginctl` için **systemd** (journal modu için de systemd gerekir)

### Python paketleri

Depoda: `pip install -r requirements.txt`  
(`requests`, `PyYAML`, `evdev`, `opencv-python-headless` — ayrıntılar dosya içi yorumlarda.)

### İsteğe bağlı sistem araçları (kilit ihlali + medya)

**Tam** kilit ekranı uyarıları (DBus ile kilit algısı, `/dev/input`, Telegram’a **ekran** + **webcam**) için işletim sistemi paketleri gerekir: örneğin **`gdbus`** (genelde **`dbus`**), **`util-linux`** (`runuser`), Wayland için **`grim`**, **X11** için **`ffmpeg`** ve/veya **ImageMagick**. Root olmayan kullanıcılar için çoğu zaman **`input`** ve gerekiyorsa **`video`** grubu.

**Dağıtım ve masaüstüne göre tam liste:** **[DEPENDENCIES.tr.md](DEPENDENCIES.tr.md)** (Türkçe) ve **[DEPENDENCIES.md](DEPENDENCIES.md)** (English).

## Tek komutla kurulum (systemd)

Depo kökünden:

```bash
cd /path/to/raas
chmod +x install.sh
./install.sh
```

Root değilseniz betik **sudo** şifresi ister ve kendini yükseltilmiş haklarla yeniden çalıştırır. İsterseniz doğrudan `sudo ./install.sh` de kullanabilirsiniz.

Kurulum sonrası `/opt/raas/config/config.yaml` dosyasını düzenleyin (özellikle Telegram), ardından:

```bash
sudo systemctl restart raas
```

### Kurulum sonrası — doğrulama, alarm dosyası, sorun giderme

**1. Servis ve günlükler**

```bash
sudo systemctl status raas --no-pager
sudo journalctl -u raas -n 40 --no-pager
```

`Watching log file:` veya `Watching systemd journal` ve `Auth alert channels:` satırlarını görmelisiniz. Canlı izleme:

```bash
sudo journalctl -u raas -f
```

**2. Alarm JSON Lines dosyası (`alarm_log`)**

Varsayılan olarak eşik aşılan her uyarı **`/var/log/raas/alarms.jsonl`** dosyasına eklenir (`alarm_log.path` ile değiştirilebilir; satır başına bir JSON). Yeni kayıtları izlemek için:

```bash
sudo tail -f /var/log/raas/alarms.jsonl
```

- **`channel`:** `auth_log` (auth/secure olayları) veya `lock_intrusion` (kilit ekranı).
- **`notify_delivered`** / **`deliveries`:** Telegram/webhook gönderimi başarılı mı. `notify_attempted` true iken `notify_delivered` false ise `journalctl` içinde `Telegram API error` arayın (token, `chat_id`, veya **`api_base_url` içinde `/bot` olmamalı** — Telegram bölümüne bakın).
- **`raw_line`:** günlükten kesit (hassas veri; dosya izinlerini sıkı tutun).

İsteğe bağlı: **`jq`** yüklüyse `sudo tail -f /var/log/raas/alarms.jsonl | jq -c .`

Dosya **boş** veya **güncellenmiyorsa:** henüz `risk.notify_threshold` üzerinde olay yok; veya **`log.tail_from_end: true`** iken yalnızca servis başladıktan **sonra** yazılan satırlar işlenir (test için hatalı SSH, `sudo` vb. üretin). `alarm_log.enabled` açık olsun; `/var/log/raas/` oluşturulabilsin (varsayılan servis **root** çalışır).

**3. HTTP health (YAML’da açıksa)**

`health.enabled: true` iken `curl -s http://127.0.0.1:8765/health` ile sayaçlar ve son olay türü okunabilir.

**4. Sık karşılaşılan durumlar**

| Belirti | Bakılacak yer |
|--------|----------------|
| Servis çalışmıyor | `journalctl -u raas -b`; YAML sözdizimi; `/opt/raas/.venv` |
| Journal’da `Event ... risk=` yok | Yeni auth satırı yok (`tail_from_end`), `log.path` / `log.backend` yanlış, log formatı ayrıştırıcıyla uyuşmuyor |
| Alarm dosyası hep boş | Eşik çok yüksek; `ignore_source_ips` hepsini süzüyor; `alarm_log.enabled: false` |
| `deliveries.telegram: false`, HTTP 404 | `api_base_url` yalnızca `https://api.telegram.org` (URL’ye `/bot` eklemeyin) |
| Telegram 401 / 400 | `bot_token` / `chat_id` hatalı; özel sohbette `/start`; grup/kanal yetkisi |

**Kaldırma:**

```bash
sudo ./scripts/uninstall.sh
sudo ./scripts/uninstall.sh --purge   # /opt/raas dahil siler (çok eski kurulumlardan kalan `/etc/raas` ağacı varsa onu da temizler)
```

## Geliştirme ortamı

```bash
cd /path/to/raas
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/config.yaml.example config/config.yaml
chmod 600 config/config.yaml
python raas.py
```

### Testler (isteğe bağlı)

```bash
pip install -r requirements-dev.txt
python -m pytest tests/
```

## systemd

Servis **root** olarak çalışır; günlük, giriş cihazları ve kamera için ek grup gerekmez. Günlükler: `journalctl -u raas -f`.

---

## Telegram yapılandırması (ayrıntılı)

Tüm Telegram ayarları **`config.yaml`** içindeki `telegram:` bölümündedir (kurulumda genelde `/opt/raas/config/config.yaml`).

### 1. Bot oluşturma ve `bot_token`

1. Telegram’da [@BotFather](https://t.me/BotFather) ile konuşun.
2. `/newbot` komutunu gönderin; bot için ad ve kullanıcı adı (`..._bot`) seçin.
3. BotFather size **HTTP API** token’ını verir; şuna benzer bir metindir:  
   `123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
4. Bu değeri yapılandırmada **`bot_token`** alanına aynen yazın (tırnak içinde önerilir).

**Güvenlik:** Token, botunuzu kontrol eden anahtardır. Kimseyle paylaşmayın; dosya izinlerini sıkı tutun (`chmod 600`).

### 2. `chat_id` — uyarıların gideceği hedef (nasıl bulunur?)

Telegram her sohbet türü için sayısal bir **`chat_id`** kullanır. RAAS bu değeri `config.yaml` içinde `chat_id` alanına yazar; böylece uyarılar doğru kişi, grup veya kanala gider.

| Hedef | Ne zaman kullanılır? |
|--------|----------------------|
| **Kişisel sohbet** | Uyarılar yalnızca size düşsün |
| **Grup / süper grup** | Ekibin gördüğü bir gruba düşsün |
| **Kanal** | Duyuru kanalına düşsün |

---

#### A) Kişisel sohbet — `chat_id` adım adım

1. Telegram’da kendi botunuzu açın ve mutlaka **`/start`** gönderin (bot sizi tanımadan API ile mesaj gönderemez).
2. Tarayıcıda şu adresi açın (`BOT_TOKEN` yerine BotFather’ın verdiği token’ı yazın):  
   `https://api.telegram.org/botBOT_TOKEN/getUpdates`
3. Dönen JSON’da `result` içinde bir veya daha fazla güncelleme görünür. Bir mesajın içinde şuna benzer bir blok arayın:  
   `"chat":{"id":123456789,...}`  
   Buradaki **`id`** sayısı sizin **`chat_id`** değerinizdir (özel sohbetlerde çoğunlukla **pozitif** tam sayı).
4. `config.yaml` içine örneğin şöyle yazın: `chat_id: "123456789"` — büyük sayılarda tırnak kullanmak güvenlidir.

**`result` boş mu?** Önce bota **`/start`** gönderin; token’ı yanlış yazmadığınızdan emin olun; sayfayı yenileyin.

**Alternatif (yalnızca kendi kullanıcı kimliğiniz):** [@userinfobot](https://t.me/userinfobot) gibi botlara mesaj attığınızda size bir **id** gösterir; kendi botunuzla **size** DM göndermek istiyorsanız bu id çoğu zaman **`chat_id`** ile aynıdır.

---

#### B) Grup / süper grup — `chat_id` adım adım

1. Botu gruba **üye olarak ekleyin** (davet ile).
2. Grupta **herhangi bir mesaj** yazın (veya botu etiketleyin); böylece `getUpdates` içinde grup güncellemesi oluşur.
3. Yine şu adresi açın:  
   `https://api.telegram.org/botBOT_TOKEN/getUpdates`
4. JSON’da ilgili mesajın `chat` → **`id`** alanına bakın. Gruplarda bu sayı genelde **negatiftir** (ör. `-1001234567890`). **Eksi işaretini** ve tüm rakamları eksiksiz kopyalayın.

---

#### C) Kanal — `chat_id` adım adım

1. Kanalı oluşturun ve botu **yönetici** yapın; **mesaj gönderme** yetkisi verin.
2. Kanala bir içerik gönderin veya botu kanala ekledikten sonra API’nin görebileceği bir etkileşim oluşturun.
3. `getUpdates` çıktısında kanal için dönen `chat` → **`id`** değerini kullanın (çoğu kanalda **negatif**, sıkça `-100...` ile başlar).

---

#### Genel notlar

- **Grup ve kanal** `chat_id` değerleri çoğu zaman **negatif** veya uzundur; JSON’daki tam değeri olduğu gibi alın.
- Uyarıların gideceği sohbetin **`id`** alanını kullanın; kullanıcı adı (`@kanal`) yerine sayısal id gerekir (Bot API `sendMessage` için).
- Aynı token ile `getUpdates` ve RAAS aynı botu paylaşır; önce bota `/start` veya grup/kanalda mesaj olmadan `getUpdates` boş kalabilir.

### 3. `config.yaml` içinde örnek

```yaml
telegram:
  enabled: true
  api_base_url: https://api.telegram.org
  bot_token: "BURAYA_BOT_TOKEN"
  chat_id: "BURAYA_CHAT_ID"
  timeout_seconds: 15
```

- **`enabled: false`** yaparsanız Telegram’a hiç istek gönderilmez (yalnızca yerel günlük / alarm dosyası).
- **`api_base_url`:** Normal kullanımda değiştirmeyin; yalnızca uyumlu bir vekil veya özel uç nokta kullanıyorsanız güncellenir.
- **`timeout_seconds`:** Bot API HTTP isteği zaman aşımı (saniye).

### 4. Çalışıp çalışmadığını test etme

Token ve chat_id doğruysa, örnek bir metin göndermek için:

```bash
curl -s -X POST "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage" \
  -d chat_id=<CHAT_ID> \
  -d text="RAAS test"
```

Başarılı yanıtta `"ok":true` görünür. Hata mesajı varsa (401, 400) token veya `chat_id` yanlıştır veya bot hedef sohbete erişemiyordur.

### 5. Sık sorunlar

- **Bot cevap vermiyor / getUpdates boş:** Bota önce özel mesajda `/start` gönderin.
- **Gruba mesaj gitmiyor:** Bot grupta mı? Grup `chat_id` doğru mu (çoğu zaman negatif)?
- **Kanala mesaj gitmiyor:** Bot kanalda **yönetici** mi ve gönderme yetkisi var mı?
- **401 Unauthorized:** Token hatalı veya iptal edilmiş.
- **400 Bad Request chat not found:** `chat_id` yanlış veya bot o sohbete hiç eklenmemiş.

### 6. RAAS özelinde

- `telegram.enabled: true` iken **`bot_token`** veya **`chat_id`** boşsa süreç çalışmaya devam eder ancak Telegram’a istek gönderilmez; günlükte uyarı görürsünüz.
- Alarm kayıtları (`alarm_log`) her uyarı için `telegram_attempted` ve `telegram_delivered` alanlarını yazar.

---

## Ayrıştırılan olaylar

SSH/OpenSSH, PAM sshd, sudo, su, FTP, telnet, posta (Dovecot/Postfix SASL), Cockpit ve yerel konsol oturumları gibi tipik `auth` / `secure` satırları desteklenir. Gürültülü trafik için `risk.notify_threshold` değerini yükseltin.

## Yapılandırma özeti

Tüm anahtarlar ve yorumlar için **`config/config.yaml.example`** dosyasına bakın.

- **`log`** — `backend`: `file` (varsayılan) veya `journal`; `path` (`auto` veya dosya yolu; dosya modu ve kilit ihlali auth ipuçları için); `tail_from_end`, `poll_interval_seconds`; `backend: journal` iken isteğe bağlı `journal.journalctl_args`.
- **`alarm_log`** — tetiklenen alarmlar için JSON satırları (varsayılan `/var/log/raas/alarms.jsonl`); auth kayıtlarında **`deliveries`** (kanal başına başarı), **`notify_attempted`** / **`notify_delivered`**, uyumluluk için **`telegram_*`** alanları.
- **`telegram`** — `bot_token`, `chat_id` vb.; **`chat_id` nasıl bulunur** için yukarıdaki **«Telegram yapılandırması (ayrıntılı)»** bölümündeki **2. maddeye** bakın (kişisel / grup / kanal).
- **`webhook`** — isteğe bağlı HTTP **POST** ile JSON (`schema: raas.alert.v1`); isteğe bağlı **`headers`**; Telegram ile **paralel** çalışabilir.
- **`risk`** — `notify_threshold` (0–100); isteğe bağlı **`notify_threshold_by_kind`** (olay türüne göre eşik); **`scores`** ile taban skor geçersiz kılma (anahtarlar ayrıştırıcı olay adlarıyla uyumlu, örn. `ssh_failed`, `ssh_accepted`, `ssh_accepted_root`); **`ignore_source_ips`** (CIDR veya tek IP — bu kaynaklardan uyarı yok); **`night_timezone`** (IANA, örn. `Europe/Istanbul`), **`night_start`** / **`night_end`**, **`night_bonus`**.
- **`health`** — isteğe bağlı JSON **`GET /`** ve **`GET /health`** (`bind`:`port`, varsayılan `127.0.0.1:8765`, `enabled: false`). Sayaçlar ve son ayrıştırılan olay bilgisi.
- **`lock_intrusion`** — kilit ekranında giriş + kamera (varsayılan açık; `enabled: false` ile kapatılır)

### Kilit ekranı, girdi, ekran görüntüsü ve kamera

Yasal olarak uygun ve izinli ortamlarda kullanın. `lock_intrusion.enabled: true` iken oturum **kilitli** sayıldığında Telegram’a **metin uyarıları** (klavye, fare düğmesi, fare hareketi için hız sınırı, dokunmatik) ve **`auth.log` üzerinden başarısız kilit açma denemeleri** (yanlış şifre satırı; **parola karakterleri evdev ile okunmaz**) gönderilir. Kilit durumu **kilitli → açılmış** olduğunda (başarılı parola vb. ile oturum açıldı) **`notify_on_unlock`** (varsayılan açık) ile ayrı bir **“oturum açıldı”** bildirimi gider. **Ekran ve webcam** görüntüleri `media_cooldown_seconds` ile seyreltilir; metin sıklığı `cooldown_seconds` ve `pointer_move_throttle_seconds` ile ayarlanır (varsayılanlar hızlı metin, yaklaşık 2.5 sn’de bir görüntü). `capture_screen`, `capture_webcam`, `watch_auth_failures`, `notify_on_unlock` vb. `config.yaml` içindedir.

- **Tam özellik için gerekli paketler:** **[DEPENDENCIES.tr.md](DEPENDENCIES.tr.md)**
- **Teşhis:** `python3 raas.py --diagnose-lock` (ekran kilitliyken çalıştırın)

## Mimari (genişletme)

- **Hat:** günlük satırı → `parser/ssh_parser.py` → isteğe bağlı IP normalize / allowlist → `utils/event_dedup.py` → `engine/risk_engine.py` → **uyarı kanalları** → `utils/alarm_file_log.py`.
- **Uyarı kanalları:** `notifier/base.py` içinde **`AlertNotifier`** (`channel_id`, `send_alert(event, risk)`). Hazır: **`TelegramNotifier`**, **`WebhookNotifier`**. Kayıt: **`notifier/build.py`** → `build_alert_notifiers(settings)`. Yeni kanal: protokolü uygula, `build_alert_notifiers` ve **`config/settings.py`** + YAML’a ekle.
- **JSON gövde:** `notifier/alert_payload.py` → `alert_to_dict()` (webhook ve ileride diğer çıkışlar).
- **Kilit ihlali** yalnızca **Telegram** üzerinden (`lock_monitor/input_watch.py`, `auth_unlock_watch.py`, `unlock_transition_watch.py`); genel kanal listesini kullanmaz.

## Geliştirici

- E-posta: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- LinkedIn: [cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)
- GitHub: [cumakurt/raas](https://github.com/cumakurt/raas)

## Lisans

Bu program özgür yazılımdır: [GNU Genel Kamu Lisansı sürüm 3](https://www.gnu.org/licenses/gpl-3.0.html) veya sonraki sürümlerinin koşulları altında yeniden dağıtabilir veya değiştirebilirsiniz. Tam metin için [`LICENSE`](LICENSE) dosyasına bakın.

---

*İngilizce sürüm: [README.md](README.md)*  
*Sistem bağımlılıkları: [DEPENDENCIES.tr.md](DEPENDENCIES.tr.md)*
