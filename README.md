# Real-Time Access Alert System (RAAS)

[![CI](https://github.com/cumakurt/raas/actions/workflows/ci.yml/badge.svg)](https://github.com/cumakurt/raas/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**RAAS** is a lightweight Python agent that tails the distribution **auth log file** or **systemd journal** (`journalctl`), parses SSH, sudo, **firewall, auditd, fail2ban**, and related security events, assigns a risk score with **severity** and optional **MITRE ATT&CK** tags, and alerts via **Telegram** (rich HTML messages, optional rate limiting and retry queue) and/or **webhook**. YAML tuning: thresholds per event kind, **ignore trusted IPs/CIDRs or usernames**, **quiet hours**, **alert coalescing**, optional **HTTP health** JSON and **Prometheus `/metrics`**, and **SIGHUP** config reload for the main watcher.

**Türkçe belge ve ayrıntılı Telegram kurulumu:** [README.tr.md](README.tr.md)

**System packages (DBus, screen capture, ffmpeg, per-distro):** [DEPENDENCIES.md](DEPENDENCIES.md) · [DEPENDENCIES.tr.md](DEPENDENCIES.tr.md)

**Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) · **Security:** [SECURITY.md](SECURITY.md)

## Linux portability

- **Auth log path:** when `log.backend` is `file` (default), set `log.path` to `auto` (recommended) to use the first existing file among `/var/log/auth.log` (Debian, Ubuntu, Kali, …) and `/var/log/secure` (RHEL, Fedora, Alma, Rocky, …). You can still set an explicit path.
- **Journal mode:** set `log.backend` to `journal` to follow **`journalctl`** (requires `journalctl` on `PATH`, i.e. systemd). Optional `log.journal.journalctl_args` lets you add filters (e.g. `SYSLOG_FACILITY=10` for auth).
- **Config file:** when you do not pass `--config`, the default is `/opt/raas/config/config.yaml` if it exists (typical install), else `config/config.yaml` next to the `config` package (development layout).
- **Screen lock:** lock detection uses `loginctl` (systemd). On systems without systemd/logind, that part is skipped gracefully.
- **Service install** requires **systemd** (`systemctl`). Other init systems are not covered by the bundled script.

## Requirements

### Core

- Python **3.10+**
- Read access to the auth log when using **file** mode (often **`adm`** group or `sudo`; the bundled **systemd** service runs as **root**), or a working **journal** when using `log.backend: journal`
- **systemd** for `install.sh` and for `loginctl`-based lock hints (and for journal mode)

### Python packages

Install from the repo: `pip install -r requirements.txt`  
(`requests`, `PyYAML`, `evdev`, `opencv-python-headless` — see file comments.)

### Optional system tools (lock intrusion + media)

For **full** lock-screen alerts (DBus lock detection, `/dev/input`, **screen** + **webcam** to Telegram), install OS packages such as **`gdbus`** (usually **`dbus`**), **`util-linux`** (`runuser`), **`grim`** (Wayland), **`ffmpeg`** and/or **ImageMagick** (X11 screen + camera). Non-root users often need the **`input`** (and sometimes **`video`**) group.

**Full matrix by distro and desktop:** **[DEPENDENCIES.md](DEPENDENCIES.md)** (English) and **[DEPENDENCIES.tr.md](DEPENDENCIES.tr.md)** (Türkçe).

## One-command install (systemd service)

From a clone of this repository:

```bash
cd /path/to/raas
chmod +x install.sh
./install.sh
```

If you are not root, the script asks for **sudo** and re-runs itself with elevated privileges. You can still run `sudo ./install.sh` directly.

The installer:

1. Detects the OS (`/etc/os-release`) and checks for systemd, `python3`, `venv`, and `rsync`
2. Shows a short report and asks for confirmation (unless `--yes`)
3. Optionally installs missing OS packages (apt / dnf / yum / pacman / zypper, by distro)
4. Copies the project to `/opt/raas` (override with `INSTALL_ROOT=...`)
5. Creates a fresh Python venv and installs `requirements.txt`
6. **Configuration:** if `${CFG_DIR}/config.yaml` is **missing**, it is created from `config/config.yaml.example`. If **`config.yaml` already exists** (upgrade/reinstall), the live file is **not** modified; the shipped example is written as **`config.yaml.new`** in the same directory so you can diff and merge new keys manually (the installer summary reminds you).
7. Installs and enables `raas.service` (runs as **root**)
8. **Starts** the service and prints a summary (paths, commands, `systemctl status` when started)

Options:

- `./install.sh --yes` / `-y` — no prompts (for automation; still installs missing packages if needed)
- `./install.sh --no-start` — install everything but do not start/restart the service
- `START_SERVICE=0` — same as skipping start

After install, edit `/opt/raas/config/config.yaml` (Telegram `bot_token`, `chat_id`, etc.) and run:

```bash
sudo systemctl restart raas
```

### After installation — verify, alarm file, troubleshooting

**1. Service and logs**

```bash
sudo systemctl status raas --no-pager
sudo journalctl -u raas -n 40 --no-pager
```

You should see lines such as `Watching log file:` or `Watching systemd journal`, and `Auth alert channels:`. Follow live output with:

```bash
sudo journalctl -u raas -f
```

**2. Alarm JSON Lines file (`alarm_log`)**

By default each alert that crosses the risk threshold is appended to **`/var/log/raas/alarms.jsonl`** (override with `alarm_log.path` in YAML). One JSON object per line. Watch new alarms:

```bash
sudo tail -f /var/log/raas/alarms.jsonl
```

- **`channel`:** `auth_log` (parsed auth/secure events) or `lock_intrusion` (screen lock activity).
- Auth records may include **`severity`**, **`mitre_techniques`**, and **`deliveries`** (per-channel success). **`notify_delivered`** / **`notify_attempted`:** if `notify_delivered` is **false** while `notify_attempted` is **true**, check `journalctl` for `Telegram API error` (wrong token, `chat_id`, or **`api_base_url` must not contain `/bot`** — see Telegram section).
- **`raw_line`:** excerpt of the original log line (sensitive; protect file permissions).

Optional: `sudo tail -f /var/log/raas/alarms.jsonl | jq -c .` if **`jq`** is installed.

If the file is **empty** or **not updating:** no event has crossed `risk.notify_threshold` yet, or **`log.tail_from_end: true`** means only lines **after** the service started are processed (generate a test event, e.g. failed SSH or `sudo`). Ensure `alarm_log.enabled` is **true** and the process can create `/var/log/raas/` (service runs as root by default).

**3. Quick health check (if enabled in YAML)**

With `health.enabled: true`, `curl -s http://127.0.0.1:8765/health` returns JSON counters (lines read, alerts, coalesce/quiet suppressions, Telegram delivery stats, config reload count, last event kind, etc.).

With **`prometheus.enabled: true`** on the same health server, `curl -s http://127.0.0.1:8765/metrics` returns **Prometheus** text metrics.

**4. Reload config without full restart**

Send **`SIGHUP`** to the main process (e.g. `kill -HUP $(pidof -x python3)` matching the service, or use `systemctl kill -s HUP raas` where appropriate). The watcher reloads YAML from disk (thresholds, ignore lists, notifiers, coalesce/quiet settings). **Lock-intrusion** threads keep their original settings until a full service restart.

**5. Common issues**

| Symptom | What to check |
|--------|----------------|
| Service not active | `journalctl -u raas -b`; config YAML syntax; Python venv under `/opt/raas/.venv` |
| No `Event ... risk=` in journal | No new auth lines (see `tail_from_end`), wrong `log.path` / `log.backend`, or parser does not match your log format |
| Alarms file always empty | Threshold too high; `ignore_source_ips` filtering; `alarm_log.enabled: false` |
| `deliveries.telegram: false`, HTTP 404 | `telegram.api_base_url` must be `https://api.telegram.org` only (no `/bot` in the URL) |
| High alert volume | Raise `risk.notify_threshold`, use `notify_threshold_by_kind`, enable `alert_coalesce`, or add `ignore_source_ips` / `ignore_users` |
| Telegram 401 / 400 | Invalid `bot_token` or `chat_id`; bot not started in DM; group/channel permissions |

**Uninstall** (stop/disable unit; files kept unless `--purge`):

```bash
sudo ./scripts/uninstall.sh
sudo ./scripts/uninstall.sh --purge   # also removes /opt/raas (and any leftover `/etc/raas` tree from old installs)
```

**Dependencies on the host:** `python3` with `venv` (e.g. `apt install python3-venv`), `rsync`, `systemd`. Optional extras for lock alerts: see **[DEPENDENCIES.md](DEPENDENCIES.md)**.

## Development setup

```bash
cd /path/to/raas
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/config.yaml.example config/config.yaml
```

Edit **`config/config.yaml`**. Protect secrets: `chmod 600 config/config.yaml`.

```bash
python raas.py
# or
python raas.py --config /path/to/custom.yaml
```

### Tests (optional)

```bash
pip install -r requirements-dev.txt
python -m pytest tests/
```

## systemd (details)

The unit runs **as root** so it can read auth logs, input devices, and the camera without extra groups. Logs: `journalctl -u raas -f`.

## Telegram

Auth alerts use **HTML** by default (`telegram.parse_mode: HTML`): structured sections (severity, human-readable event title, details, reasons, suggested checks, raw log in `<pre>`). Link previews are disabled. Lock-intrusion texts stay **plain** for safety.

### Config keys (`telegram` in YAML)

- `enabled` — turn sending on or off
- `api_base_url` — default `https://api.telegram.org`
- `bot_token` — create a bot with [@BotFather](https://t.me/BotFather) (`/newbot`) and copy the token
- `chat_id` — numeric id of the private chat, group, or channel that will receive alerts (see below)
- `timeout_seconds` — HTTP timeout for Bot API calls
- `parse_mode` — `HTML` (default) or `NONE` / `PLAIN` for plain text alerts
- `rate_limit_per_minute` — cap outgoing Telegram messages per rolling minute (`0` = unlimited); exceeded sends may be queued if retry is enabled
- `retry_enabled` — on failure or rate limit, append messages to **`retry_queue_path`** (JSON Lines) for best-effort redelivery
- `retry_queue_path` — default `/var/lib/raas/telegram_retry.jsonl`
- `high_severity_chat_id` — optional second destination (same bot token); receives alerts only when **`severity` is `high`**

If `enabled` is true but `bot_token` or `chat_id` is empty, the process keeps running and only logs locally.

### How to find `chat_id`

Every Telegram destination has a numeric **chat id** (private user, group, supergroup, or channel).

**1. Private chat (alerts only to you)**

1. In Telegram, open your bot and send **`/start`** (the bot must receive at least one message from you).
2. In a browser, open (replace `YOUR_BOT_TOKEN` with your real token):  
   `https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates`
3. In the JSON, locate `message` → `chat` → **`id`**. That number is your **`chat_id`** (private chats are usually a **positive** integer).
4. Put it in YAML as `chat_id: "123456789"` — quotes avoid issues with large numbers.

If `result` is **empty**, you forgot `/start` or the token is wrong; send `/start` again and reload the URL.

**2. Groups / supergroups**

1. Add your bot to the group (invite it like a normal member).
2. Send **any message** in the group (or mention the bot).
3. Open the same **`getUpdates`** URL. Find the latest `message` → `chat` → **`id`**. For groups it is usually **negative** (e.g. `-1001234567890`). Copy it **exactly**, including the minus sign.

**3. Channels**

1. Add the bot as a **channel administrator** with permission to **post messages**.
2. Post something in the channel (or trigger an update involving the bot).
3. Use **`getUpdates`** and read `chat` → **`id`** (often negative, frequently starting with `-100...`).

**Other helpers**

- Bots such as [@userinfobot](https://t.me/userinfobot) show your **user id** when you message them; that id is the same as **`chat_id`** for sending DMs **to you** via your own bot.
- Always use the **`id`** value returned by the Bot API for the chat where you want RAAS alerts.

### Quick test

```bash
curl -s "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage" \
  -d chat_id=<CHAT_ID> \
  -d text="RAAS test"
```

A successful delivery includes `"ok":true` in the JSON.

## Parsed log events (auth / secure / journal)

The unified parser (`parser/log_parser.py`) first applies **SSH/OpenSSH** rules (accepted logins, failed password/publickey/keyboard-interactive, invalid user, max auth attempts, “too many authentication failures”, preauth disconnects), then **PAM sshd** failures (deduplicated when they mirror a recent sshd failure for the same user/IP), **sudo** / **su** / **root context**, **vsftpd/proftpd**, **telnetd**, **Dovecot/Postfix SASL**, **Cockpit**, **local console** login, and **extra** patterns when present in the same stream: **auditd** (login failures, AVC denied, account change heuristics), **UFW BLOCK**, **nftables** DROP lines, **fail2ban** ban/unban, **polkit**, **VPN** auth failures, **PostgreSQL/MySQL** auth failures, **container** registry hints, and **sudo** authentication failures. Heuristics vary by distro log format—see `parser/security_extras.py`. Tune `risk.notify_threshold` and **`notify_threshold_by_kind`** if a source is noisy.

## Configuration overview

See **`config/config.yaml.example`** for all keys and comments.

- **`log`** — `backend`: `file` (default) or `journal`; `path` (`auto` or explicit file, used for file mode and for lock-intrusion auth hints); `tail_from_end`, `poll_interval_seconds`; optional `journal.journalctl_args` when `backend` is `journal`.
- **`alarm_log`** — append-only **JSON Lines** file (default `/var/log/raas/alarms.jsonl`) for every alert that crosses the effective threshold (auth events) and for lock-intrusion events. Auth records include **`severity`**, **`mitre_techniques`**, **`deliveries`** (per-channel success), **`notify_attempted`** / **`notify_delivered`**, and legacy **`telegram_*`** fields. Disable with `enabled: false` or point `path` elsewhere (ensure the process can create/write the file).
- **`telegram`** — see [Telegram](#telegram) (includes `parse_mode`, rate limit, retry queue, **`high_severity_chat_id`**)
- **`webhook`** — optional HTTP **POST** of JSON (`schema: raas.alert.v1`, includes **`severity`** and **`mitre_techniques`**) to a URL (e.g. SIEM); optional **`headers`**; runs **in parallel** with Telegram when both are enabled.
- **`risk`** — `notify_threshold` (0–100); optional **`notify_threshold_by_kind`** (per event kind); optional **`scores`** overrides (keys match parser event kinds, e.g. `ssh_failed`, `ssh_accepted`, `ssh_accepted_root`, `sudo_auth_failure`, …); **`ignore_source_ips`** (CIDR or single IP—no alerts from those remote addresses); **`ignore_users`** (local/remote usernames to skip, lowercase match on `event.user`); **`night_timezone`** (IANA name, e.g. `Europe/London`), **`night_start`** / **`night_end`** (hour window), **`night_bonus`** (extra points at night).
- **`quiet_hours`** — optional daily window (`enabled`, `start_hour`/`end_hour` or YAML `start`/`end`, `timezone`) to **suppress** Telegram/webhook (alarm file can still record events that cross the threshold).
- **`alert_coalesce`** — merge bursts: same (kind, user, IP) within **`window_seconds`** collapses duplicates and emits a summary when the window rolls (see `utils/burst_suppress.py`).
- **`health`** — optional JSON **`GET /`** and **`GET /health`** on `bind`:`port` (default `127.0.0.1:8765`, `enabled: false`). Extended counters (coalesce/quiet suppressions, Telegram success/fail, config reloads, etc.).
- **`prometheus`** — when `enabled: true` and **`health.enabled`**, **`GET /metrics`** on the **same** bind/port exposes **Prometheus** text metrics.
- **`lock_intrusion`** — alert when input is detected while the session is locked (enabled by default; set `enabled: false` to turn off)

### Lock screen, input, screen capture, and webcam

By default, `lock_intrusion.enabled` is **true**. When the session is considered **locked** (DBus screensaver / `loginctl` / lock-helper processes), RAAS sends **Telegram text alerts** for input (keyboard, mouse buttons, throttled pointer movement, touchpad) and polls **`auth.log` for failed greeter / unlock attempts** (wrong password at lock screen — the log line is included; **password characters are never read from evdev**). When the lock state goes from **locked to unlocked** (successful unlock), **`notify_on_unlock`** (default true) sends a separate **“session unlocked”** alert. **Screen and webcam** images are **throttled** by `media_cooldown_seconds` to reduce Telegram rate limits; text can be as frequent as `cooldown_seconds` and `pointer_move_throttle_seconds` allow (defaults favor fast text, ~2.5s between captures). Configure `capture_screen`, `capture_webcam`, `watch_auth_failures`, `notify_on_unlock`, and timing keys in YAML.

- **Required OS tools for full functionality:** see **[DEPENDENCIES.md](DEPENDENCIES.md)** (per-distro package names).
- **Diagnosis:** `python3 raas.py --diagnose-lock` (run while the screen is locked to verify DBus).
- Use only where you have the legal right and consent to record.

## Architecture (extending)

- **Pipeline:** log line → `parser/log_parser.py` (SSH/core + `parser/security_extras.py` heuristics) → optional IP normalize / allowlist → `utils/event_dedup.py` → `engine/risk_engine.py` (`RiskResult`: **severity**, **MITRE** tags via `engine/mitre.py`) → **alert channels** → `utils/alarm_file_log.py`. Legacy `parser/ssh_parser.py` remains for focused SSH unit tests.
- **Alert channels:** `notifier/base.py` defines **`AlertNotifier`** (`channel_id`, `send_alert(event, risk)`). Built-in: **`TelegramNotifier`**, **`WebhookNotifier`**, optional **high-severity** routing in **`notifier/build.py`**. Registry: `build_alert_notifiers(settings)`. Add a new channel by implementing the protocol, wiring it in `build_alert_notifiers`, and extending **`config/settings.py`** + YAML.
- **Structured payload:** `notifier/alert_payload.py` → `alert_to_dict()` for webhook JSON and future exporters.
- **Lock intrusion** stays on **Telegram only** (`lock_monitor/input_watch.py`, `auth_unlock_watch.py`, `unlock_transition_watch.py`, `intrusion_notify.py`); it does not use the generic notifier list.

## Developer

- Email: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- LinkedIn: [cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)
- GitHub: [cumakurt/raas](https://github.com/cumakurt/raas)

## License

This program is free software: you can redistribute it and/or modify it under the terms of the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html) or later. See the [`LICENSE`](LICENSE) file.
