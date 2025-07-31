# ExWiFi - WiFi Security Testing Tool

A powerful WiFi security testing tool for Termux that allows you to perform various WiFi attacks and security assessments.

## ⚠️ Disclaimer

This tool is for **educational and authorized testing purposes only**. Only use it on networks you own or have explicit permission to test. Unauthorized access to computer networks is illegal.

## 📋 Requirements

- **Root access** (required)
- Termux with root-repo
- Python
- Network tools (wpa-supplicant, pixiewps, iw)

## 🚀 Installation

```bash
apt update && apt upgrade
pkg install -y root-repo
pkg install -y git tsu python wpa-supplicant pixiewps iw
git clone https://github.com/FakeErrorX/ExWiFi
cd ExWiFi
```

## 📖 Usage

### Basic Commands

**Show available networks and start Pixie Dust attack:**
```bash
sudo python ErrorX.py -i wlan0 -K
```

**Start Pixie Dust attack on a specific BSSID:**
```bash
sudo python ErrorX.py -i wlan0 -b 00:91:4C:C3:AC:28 -K
```

**Launch online WPS bruteforce with specified PIN prefix:**
```bash
sudo python ErrorX.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234
```

## ⚡ Quick Start

1. **Turn off your WiFi** before starting
2. Run the tool with appropriate parameters
3. Follow the on-screen instructions

## 🔧 Troubleshooting

### Common Issues

**"Device or resource busy (-16)"**
- **Solution**: Turn on WiFi, then turn it off again before running the tool

**Permission denied**
- **Solution**: Ensure you're running with `sudo` and have root access

**Network interface not found**
- **Solution**: Check available interfaces with `iwconfig` or `ip link show`

## 📝 Parameters

| Parameter | Description |
|-----------|-------------|
| `-i` | Network interface (e.g., wlan0) |
| `-K` | Start Pixie Dust attack |
| `-b` | Target BSSID |
| `-B` | Enable bruteforce mode |
| `-p` | PIN prefix for bruteforce |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

---

**Remember**: Always use this tool responsibly and only on networks you own or have permission to test.
