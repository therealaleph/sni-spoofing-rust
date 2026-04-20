# Prebuilt Binaries

This folder contains the prebuilt binaries from the latest release, committed directly to the repository for users who cannot access the GitHub Releases page.

Current version: **v0.5.1**

| File | Platform |
|---|---|
| `sni-spoof-rs-linux-amd64` | Linux x86_64 |
| `sni-spoof-rs-linux-arm64` | Linux aarch64 |
| `sni-spoof-rs-macos-amd64` | macOS x86_64 |
| `sni-spoof-rs-macos-arm64` | macOS Apple Silicon |
| `sni-spoof-rs-windows-amd64.zip` | Windows x86_64 (contains exe + WinDivert.dll + WinDivert64.sys) |

## Download via git clone

```
git clone https://github.com/therealaleph/sni-spoofing-rust.git
cd sni-spoofing-rust/releases
```

## Download via zip

Go to [github.com/therealaleph/sni-spoofing-rust](https://github.com/therealaleph/sni-spoofing-rust), click the green **Code** button, then **Download ZIP**. Extract the zip, then the binaries are in the `releases/` folder.

## After download

On Linux/macOS, mark the binary executable:

```
chmod +x sni-spoof-rs-linux-amd64
sudo ./sni-spoof-rs-linux-amd64 config.json
```

On Windows, extract the zip (keep `.exe`, `.dll`, `.sys` together), then run as Administrator.

---

## فایل‌های اجرایی

این پوشه شامل فایل‌های اجرایی آخرین نسخه است که مستقیماً در ریپازیتوری قرار گرفته‌اند برای کاربرانی که به صفحه GitHub Releases دسترسی ندارند.

نسخه فعلی: **v0.5.1**

### دانلود از طریق ZIP

به [github.com/therealaleph/sni-spoofing-rust](https://github.com/therealaleph/sni-spoofing-rust) بروید، روی دکمه سبز **Code** کلیک کنید و **Download ZIP** را بزنید. پس از اکسترکت، فایل‌ها در پوشه `releases/` هستند.

### بعد از دانلود

در لینوکس/مک ابتدا اجرایی کنید:

```
chmod +x sni-spoof-rs-linux-amd64
sudo ./sni-spoof-rs-linux-amd64 config.json
```

در ویندوز zip را اکسترکت کنید (فایل‌های `.exe`، `.dll` و `.sys` کنار هم باشند) و با Administrator اجرا کنید.
