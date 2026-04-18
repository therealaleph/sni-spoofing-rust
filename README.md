# sni-spoof-rs

Rust implementation of [patterniha's SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) DPI bypass technique. All credit for the original idea and method goes to [@patterniha](https://github.com/patterniha).

A TCP forwarder that injects a fake TLS ClientHello with an intentionally wrong TCP sequence number right after the 3-way handshake. Stateful DPI reads the fake SNI and whitelists the flow. The real server drops the packet (out-of-window seq). Real traffic then passes through undetected.

**[English Guide](#setup-guide)** | **[Persian Guide](#%D8%B1%D8%A7%D9%87%D9%86%D9%85%D8%A7%DB%8C-%D9%81%D8%A7%D8%B1%D8%B3%DB%8C)**

## Platforms

- **Linux** -- AF_PACKET raw sockets. Requires root or `CAP_NET_RAW`.
- **macOS** -- BPF device. Requires root.
- **Windows** -- WinDivert driver. Requires Administrator.

## Build

```
cargo build --release
```

Pre-built binaries for Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64) are available on the [releases](https://github.com/therealaleph/sni-spoofing-rust/releases) page.

## Setup Guide

This tool works with VLESS/VMess configs that go through Cloudflare (CDN-based configs). Your server must be behind Cloudflare.

### Step 1: Find your server's Cloudflare IP

Your v2ray/xray config has a server address (a domain like `myserver.example.com`). Resolve it to get the IP:

```
nslookup myserver.example.com
```

You should get a Cloudflare IP (usually starts with `104.`, `172.67.`, `141.101.`, etc).

### Step 2: Create config.json

```json
{
  "listeners": [
    {
      "listen": "0.0.0.0:40443",
      "connect": "CLOUDFLARE_IP:443",
      "fake_sni": "security.vercel.com"
    }
  ]
}
```

Replace `CLOUDFLARE_IP` with the IP from step 1. The `fake_sni` can be any domain that is allowed by your DPI (a well-known site behind Cloudflare works best).

| Field | Description |
|---|---|
| `listen` | Local address and port to listen on |
| `connect` | Cloudflare IP and port (must be an IP, not a hostname) |
| `fake_sni` | SNI for the fake ClientHello (max 219 bytes) |
| `conn_timeout_sec` | Seconds to wait for the upstream TCP connection to complete (default: `5`) |
| `handshake_timeout_sec` | Seconds to wait for the sniffer to confirm the fake packet was sent (default: `2`) |
| `keepalive_time_sec` | Seconds of idle before TCP keepalive probes begin (default: `11`) |
| `keepalive_interval_sec` | Seconds between individual TCP keepalive probes (default: `2`) |

Multiple listeners are supported -- each maps to one upstream.

### Step 3: Edit your v2ray/xray config

In your VLESS/VMess client config, change:

- **Address**: from `myserver.example.com` (or its IP) to `127.0.0.1`
- **Port**: to the `listen` port from config.json (e.g. `40443`)
- **Keep everything else the same** (SNI, host, path, UUID, etc.)

Example -- if your original config has:
```
address: myserver.example.com
port: 443
```

Change it to:
```
address: 127.0.0.1
port: 40443
```

The tool sits between your v2ray client and the server. Your client connects to the tool, the tool handles the DPI bypass, and forwards traffic to Cloudflare.

### Step 4: Run

```
# Linux/macOS
sudo ./sni-spoof-rs config.json

# Windows (run as Administrator)
sni-spoof-rs.exe config.json
```

**Windows note:** The Windows download is a zip containing `sni-spoof-rs.exe` and `WinDivert64.sys`. Keep both files in the same folder. The `.sys` file is the kernel driver that WinDivert needs to intercept packets.

Then connect with your v2ray/xray client as usual.

### Logging

The default log level is `warn` -- the tool runs silent unless something goes wrong. No connection metadata is logged by default.

Set `RUST_LOG` for verbosity when debugging:

```
sudo RUST_LOG=info ./sni-spoof-rs config.json
sudo RUST_LOG=debug ./sni-spoof-rs config.json
```

## How it works

1. Client connects to the listener, tool dials the upstream, kernel does the TCP 3-way handshake normally.
2. A raw packet sniffer captures the outbound SYN (records ISN) and the 3rd-handshake ACK.
3. After the 3rd ACK, a fake TLS ClientHello is injected with `seq = ISN + 1 - len(fake)`. This sequence number is before the server's receive window.
4. DPI parses the fake packet, sees an allowed SNI, and whitelists the connection.
5. The server drops the fake packet (out-of-window).
6. Tool waits for the server's ACK with `ack == ISN + 1` confirming the fake was ignored.
7. Bidirectional relay starts. The real TLS handshake and all subsequent traffic flow normally.

---

## راهنمای فارسی

این ابزار با کانفیگ‌های VLESS/VMess که از Cloudflare عبور می‌کنند کار می‌کند. سرور شما باید پشت Cloudflare باشد.

### مرحله ۱: پیدا کردن IP کلادفلر سرور

آدرس سرور در کانفیگ v2ray شما یک دامنه است (مثل `myserver.example.com`). IP آن را پیدا کنید:

```
nslookup myserver.example.com
```

باید یک IP کلادفلر بگیرید (معمولا با `104.`، `172.67.`، `141.101.` شروع می‌شود).

### مرحله ۲: ساخت config.json

```json
{
  "listeners": [
    {
      "listen": "0.0.0.0:40443",
      "connect": "IP_CLOUDFLARE:443",
      "fake_sni": "security.vercel.com"
    }
  ]
}
```

به جای `IP_CLOUDFLARE` آی‌پی مرحله ۱ را بگذارید. مقدار `fake_sni` می‌تواند هر دامنه‌ای باشد که فیلتر نیست (یک سایت معروف پشت کلادفلر بهتر جواب می‌دهد).

| فیلد | توضیح |
|---|---|
| `listen` | آدرس و پورت محلی برای گوش دادن |
| `connect` | آی‌پی و پورت کلادفلر (باید IP باشد، نه دامنه) |
| `fake_sni` | SNI برای ClientHello جعلی (حداکثر ۲۱۹ بایت) |
| `conn_timeout_sec` | ثانیه‌های انتظار برای برقراری اتصال  (پیش‌فرض: `5`) |
| `handshake_timeout_sec` | ثانیه‌های انتظار برای تأیید ارسال پکت جعلی توسط sniffer (پیش‌فرض: `2`) |
| `keepalive_time_sec` | ثانیه‌های بی‌فعالیتی قبل از شروع پروب‌های TCP keepalive (پیش‌فرض: `11`) |
| `keepalive_interval_sec` | فاصله زمانی بین پروب‌های TCP keepalive به ثانیه (پیش‌فرض: `2`) |

### مرحله ۳: تغییر کانفیگ v2ray/xray

در کانفیگ VLESS/VMess خود این تغییرات را بدهید:

- **آدرس (address)**: عوض کنید به `127.0.0.1`
- **پورت (port)**: عوض کنید به پورت listen از config.json (مثلا `40443`)
- **بقیه تنظیمات را دست نزنید** (SNI، host، path، UUID و غیره)

مثال -- اگر کانفیگ اصلی شما اینطوری است:
```
address: myserver.example.com
port: 443
```

تغییر دهید به:
```
address: 127.0.0.1
port: 40443
```

### مرحله ۴: اجرا

```
# لینوکس/مک
sudo ./sni-spoof-rs config.json

# ویندوز (با دسترسی Administrator اجرا کنید)
sni-spoof-rs.exe config.json
```

**نکته ویندوز:** فایل دانلودی ویندوز یک zip است که شامل `sni-spoof-rs.exe` و `WinDivert64.sys` می‌باشد. هر دو فایل باید در یک پوشه باشند. فایل `.sys` درایور کرنل WinDivert است که برای رهگیری پکت‌ها لازم است.

بعد از اجرا، کلاینت v2ray/xray خود را مثل همیشه وصل کنید.

### دانلود

فایل‌های اجرایی آماده برای لینوکس، مک و ویندوز از صفحه [releases](https://github.com/therealaleph/sni-spoofing-rust/releases) قابل دانلود هستند.

## License

MIT
