# RAAS — system and optional dependencies

This file lists **everything** RAAS may use so you can install the right packages on **different distributions** and **desktop environments** (GNOME, KDE Plasma, MATE, XFCE, Cinnamon, Wayland or X11).

- **Türkçe:** [DEPENDENCIES.tr.md](DEPENDENCIES.tr.md)

---

## 1. Always required

| Purpose | Notes |
|--------|--------|
| **Python** 3.10+ | Interpreter |
| **systemd** + **loginctl** | Service install script; lock fallback via `LockedHint` |
| **pip packages** | See `requirements.txt` (`requests`, `PyYAML`, `evdev`, `opencv-python-headless`) |
| **Read auth log** | Usually `/var/log/auth.log` or `/var/log/secure` — user often needs **`adm`** group (or run as root) |
| **Network** | Outbound HTTPS to Telegram Bot API (unless `telegram.enabled: false`) |

---

## 2. Python dependencies (`requirements.txt`)

| Package | Role |
|---------|------|
| `requests` | Telegram HTTP API |
| `PyYAML` | Config loading |
| `evdev` | Lock-intrusion: keyboard/mouse from `/dev/input/event*` |
| `opencv-python-headless` | Optional webcam capture if `ffmpeg` is not used for camera |

Install: `pip install -r requirements.txt` (inside the project venv).

---

## 3. Lock detection (DBus + session bus)

Screen lock is detected using **session** DBus (`GetActive` on screensaver services) and/or **loginctl** `LockedHint`, plus optional **pgrep** for standalone lockers (`i3lock`, `swaylock`, …).

| Tool | Role |
|------|------|
| **`gdbus`** | Calls `org.gnome.ScreenSaver`, `org.mate.ScreenSaver`, KDE/XFCE/Cinnamon, etc. Usually in the **`dbus`** or **`dbus-x11`** package (name varies). |
| **`runuser`** (util-linux) | When RAAS runs as **root**, session DBus is queried **as the desktop user** (`runuser -u … gdbus`). Package: **`util-linux`** (almost always installed). |

**Diagnosis:** `python3 raas.py --diagnose-lock`

---

## 4. Screen capture (lock intrusion — `capture_screen: true`)

| Stack | Tool | Typical package |
|-------|------|-----------------|
| **Wayland** | `grim` | `grim` |
| **X11** | `ffmpeg` (`x11grab`) | `ffmpeg` |
| **X11** (alternative) | ImageMagick `import` | Debian/Ubuntu: `imagemagick`; Fedora: `ImageMagick`; Arch: `imagemagick` |

RAAS reads **DISPLAY** / **WAYLAND_DISPLAY** from the **graphical session leader** (`loginctl` → `leader` → `/proc/.../environ`). If these are missing, screen capture is skipped.

---

## 5. Webcam (lock intrusion — `capture_webcam: true`)

| Priority | Tool | Package |
|----------|------|---------|
| Preferred | `ffmpeg` (V4L2) | `ffmpeg` |
| Fallback | OpenCV (Python) | Already via `opencv-python-headless` |

Device path defaults to `/dev/video0`. User may need **`video`** group (or root).

---

## 6. Input devices (`/dev/input`)

The lock-intrusion thread opens **evdev** devices. Non-root users usually need the **`input`** group:

```bash
sudo usermod -aG input YOUR_USER
```

Then log out and back in. **Root** (default systemd service) can open devices without this.

---

## 7. Install commands by family (optional extras)

Install **after** base Python/venv. Package names are indicative — use your distro’s search if a name differs.

### Debian / Ubuntu / Linux Mint / Kali / Pop!_OS

```bash
sudo apt-get update
sudo apt-get install -y \
  dbus dbus-x11 util-linux \
  grim ffmpeg imagemagick
```

- `gdbus` is provided by **`dbus`** / **`dbus-x11`**.
- `runuser` → **`util-linux`**.

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

## 8. Desktop environments

| DE | DBus service (examples) | Screen capture |
|----|-------------------------|----------------|
| GNOME | `org.gnome.ScreenSaver` | Wayland: `grim`; X11: `ffmpeg` / `import` |
| MATE | `org.mate.ScreenSaver` | Same |
| Cinnamon | `org.cinnamon.ScreenSaver` | Same |
| KDE Plasma | `org.kde.screensaver` | Same |
| XFCE | `org.xfce.ScreenSaver` | Same |
| i3/sway + `swaylock` / `i3lock` | May have no DBus saver — **pgrep** fallback | `grim` on sway (Wayland) |

---

## 9. Minimal vs full feature set

| Feature | Minimal install | Full lock + Telegram media |
|---------|-----------------|------------------------------|
| Auth log + risk + Telegram text | Python + `requirements.txt` + auth log read | + stable network |
| Lock detection (DBus) | + `gdbus` + `runuser` when root | As above |
| Lock + input events | + `evdev` (pip) + `/dev/input` access | + `input` group if not root |
| Screen + webcam alerts | + §7 packages | Recommended |

---

## 10. Troubleshooting

- **`No accessible input devices`:** add user to **`input`** group or run as root.
- **Lock never detected:** run `--diagnose-lock` while the screen is locked; ensure **`gdbus`** works; as root ensure **`runuser`** exists.
- **Screen capture skipped:** install **`grim`** (Wayland) or **`ffmpeg`** / **ImageMagick** (X11); ensure a graphical session exists for the user.
- **Webcam fails:** install **`ffmpeg`**, check **`video`** group and `/dev/video*`.
