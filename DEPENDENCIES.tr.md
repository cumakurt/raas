# RAAS — sistem ve isteğe bağlı bağımlılıklar

Bu dosya, **farklı dağıtımlarda** ve **masaüstü ortamlarında** (GNOME, KDE Plasma, MATE, XFCE, Cinnamon, Wayland veya X11) RAAS’ın kullandığı araçları listeler.

- **English:** [DEPENDENCIES.md](DEPENDENCIES.md)

---

## 1. Zorunlu olanlar

| Amaç | Not |
|------|-----|
| **Python** 3.10+ | Çalışma zamanı |
| **systemd** + **loginctl** | Kurulum betiği; kilit için `LockedHint` yedek yolu |
| **pip paketleri** | `requirements.txt` (`requests`, `PyYAML`, `evdev`, `opencv-python-headless`) |
| **Auth günlüğü okuma** | Genelde `/var/log/auth.log` veya `/var/log/secure` — kullanıcı çoğu zaman **`adm`** grubunda olmalı (veya root) |
| **Ağ** | Telegram Bot API için dışarı HTTPS (`telegram.enabled: true` ise) |

---

## 2. Python bağımlılıkları (`requirements.txt`)

| Paket | Görev |
|-------|--------|
| `requests` | Telegram HTTP API |
| `PyYAML` | Yapılandırma |
| `evdev` | Kilit ihlali: `/dev/input/event*` üzerinden klavye/fare |
| `opencv-python-headless` | `ffmpeg` kullanılmıyorsa web kamerası yedek yakalama |

Kurulum: proje sanal ortamında `pip install -r requirements.txt`.

---

## 3. Kilit algılama (DBus + oturum veri yolu)

Kilit; **oturum** DBus’ta (`GetActive`) ekran koruyucu servisleri, **loginctl** `LockedHint` ve isteğe bağlı **pgrep** (`i3lock`, `swaylock`, …) ile tespit edilir.

| Araç | Görev |
|------|--------|
| **`gdbus`** | `org.gnome.ScreenSaver`, `org.mate.ScreenSaver`, KDE/XFCE/Cinnamon vb. Genelde **`dbus`** veya **`dbus-x11`** paketinde. |
| **`runuser`** (util-linux) | RAAS **root** iken oturum DBus’u **masaüstü kullanıcısı** olarak sorgular. Paket: **`util-linux`**. |

Teşhis: `python3 raas.py --diagnose-lock`

---

## 4. Ekran görüntüsü (`capture_screen: true`)

| Ortam | Araç | Tipik paket |
|-------|------|-------------|
| **Wayland** | `grim` | `grim` |
| **X11** | `ffmpeg` (`x11grab`) | `ffmpeg` |
| **X11** (alternatif) | ImageMagick `import` | Debian/Ubuntu: `imagemagick`; Fedora: `ImageMagick`; Arch: `imagemagick` |

**DISPLAY** / **WAYLAND_DISPLAY** değerleri grafik **oturum liderinin** ortamından okunur (`loginctl` → `leader` → `/proc/.../environ`). Yoksa ekran yakalama atlanır.

---

## 5. Web kamerası (`capture_webcam: true`)

| Öncelik | Araç | Paket |
|---------|------|-------|
| Tercih | `ffmpeg` (V4L2) | `ffmpeg` |
| Yedek | OpenCV (Python) | `opencv-python-headless` (pip) |

Varsayılan cihaz `/dev/video0`. Gerekirse kullanıcı **`video`** grubunda olmalı (veya root).

---

## 6. Giriş cihazları (`/dev/input`)

Kilit izleme **evdev** ile açar. Root olmayan kullanıcılar için genelde **`input`** grubu:

```bash
sudo usermod -aG input KULLANICI
```

Oturumu kapatıp açın. **systemd servisi root** olarak çalıştığında ek grup gerekmez.

---

## 7. Dağıtıma göre kurulum (isteğe bağlı ek paketler)

Temel Python/venv kurulumundan sonra. Paket adları örnektir; dağıtımınıza göre `apt search` / `dnf search` kullanın.

### Debian / Ubuntu / Linux Mint / Kali / Pop!_OS

```bash
sudo apt-get update
sudo apt-get install -y \
  dbus dbus-x11 util-linux \
  grim ffmpeg imagemagick
```

### Fedora / RHEL / Rocky / Alma (dnf)

```bash
sudo dnf install -y \
  dbus dbus-x11 util-linux \
  grim ffmpeg ImageMagick
```

### Arch / Manjaro (pacman)

```bash
sudo pacman -S --needed \
  dbus util-linux \
  grim ffmpeg imagemagick
```

### openSUSE (zypper)

```bash
sudo zypper install -y \
  dbus-1 util-linux \
  grim ffmpeg ImageMagick
```

---

## 8. Masaüstü ortamları

| Ortam | DBus örnekleri | Ekran yakalama |
|-------|----------------|----------------|
| GNOME | `org.gnome.ScreenSaver` | Wayland: `grim`; X11: `ffmpeg` / `import` |
| MATE | `org.mate.ScreenSaver` | Aynı |
| Cinnamon | `org.cinnamon.ScreenSaver` | Aynı |
| KDE Plasma | `org.kde.screensaver` | Aynı |
| XFCE | `org.xfce.ScreenSaver` | Aynı |
| i3/sway + `swaylock` / `i3lock` | DBus olmayabilir — **pgrep** yedek | Sway’de Wayland: `grim` |

---

## 9. Özet: minimum vs tam özellik

| Özellik | Minimum | Tam kilit + Telegram medya |
|---------|---------|----------------------------|
| Auth günlüğü + risk + Telegram metni | Python + `requirements.txt` + günlük okuma | + internet |
| Kilit (DBus) | + `gdbus` + root iken `runuser` | Yukarıdaki gibi |
| Kilit + girdi olayları | + pip `evdev` + `/dev/input` erişimi | Root değilse + `input` grubu |
| Ekran + kamera uyarıları | + §7 paketleri | Önerilir |

---

## 10. Sorun giderme

- **`No accessible input devices`:** **`input`** grubu veya root.
- **Kilit hiç algılanmıyor:** kilitliyken `--diagnose-lock`; **`gdbus`** kurulu mu; root’ta **`runuser`** var mı.
- **Ekran yakalanmıyor:** Wayland’da **`grim`**, X11’de **`ffmpeg`** veya **ImageMagick**; grafik oturumu var mı.
- **Kamera açılmıyor:** **`ffmpeg`**, **`video`** grubu, `/dev/video*`.
