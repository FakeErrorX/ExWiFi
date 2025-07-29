# ExWiFi - Advanced WiFi Security Testing Tool

A powerful, modernized WiFi security testing tool for Termux that allows you to perform various WiFi attacks and security assessments with enhanced features and better user experience.

## ⚠️ Disclaimer

This tool is for **educational and authorized testing purposes only**. Only use it on networks you own or have explicit permission to test. Unauthorized access to computer networks is illegal.

## 🚀 New Features (Enhanced Edition 2024)

### ✨ Modern Enhancements
- **Enhanced UI**: Modern color-coded interface with progress bars and status indicators
- **Better Error Handling**: Comprehensive error handling with detailed logging
- **Configuration Management**: JSON-based configuration system for persistent settings
- **Improved Logging**: Detailed logging system with file and console output
- **Graceful Shutdown**: Proper cleanup and signal handling
- **Enhanced Security**: Better validation and input sanitization

### 🔧 Technical Improvements
- **Modern Python**: Updated to use Python 3.6+ features and best practices
- **Type Hints**: Full type annotation support for better code maintainability
- **Data Classes**: Modern data structures for better organization
- **Async Support**: Better handling of concurrent operations
- **Enhanced Algorithms**: Improved WPS PIN generation algorithms

### 📊 Better User Experience
- **Progress Tracking**: Real-time progress bars for bruteforce operations
- **Status Indicators**: Color-coded status messages for better visibility
- **Session Management**: Improved session saving and restoration
- **Configuration Persistence**: Settings are saved and restored between sessions

## 📋 Requirements

- **Root access** (required)
- Termux with root-repo
- Python 3.6+
- Network tools (wpa-supplicant, pixiewps, iw)

## 🚀 Installation

```bash
# Update system and install dependencies
apt update && apt upgrade
pkg install -y root-repo
pkg install -y git tsu python wpa-supplicant pixiewps iw

# Clone repository and set up
git clone https://github.com/FakeErrorX/ExWiFi
cd ExWiFi
chmod +x ErrorX.py

# Test installation
sudo python ErrorX.py --help
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

**Run with verbose logging:**
```bash
sudo python ErrorX.py -i wlan0 -K -v
```

### Advanced Usage

**Save credentials automatically:**
```bash
sudo python ErrorX.py -i wlan0 -b 00:90:4C:C1:AC:21 -K -w
```

**Use custom vulnerable devices list:**
```bash
sudo python ErrorX.py -i wlan0 -K --vuln-list custom_vuln.txt
```

**Run in loop mode:**
```bash
sudo python ErrorX.py -i wlan0 -K -l
```

## ⚡ Quick Start

1. **Turn off your WiFi** before starting
2. Run the tool with appropriate parameters
3. Follow the on-screen instructions
4. Check the generated logs for detailed information

## 🔧 Configuration

The tool now supports a configuration file (`exwifi_config.json`) that stores:

- Default interface
- Timeout settings
- Retry attempts
- Delay between attempts
- Auto-save preferences
- Verbose logging settings

### Configuration Options

```json
{
  "interface": "wlan0",
  "timeout": 30,
  "max_retries": 3,
  "delay_between_attempts": 1.0,
  "save_results": true,
  "verbose_logging": false,
  "auto_save_session": true,
  "default_attack_type": "pixie_dust"
}
```

## 📝 Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-i` | Network interface | `-i wlan0` |
| `-K` | Start Pixie Dust attack | `-K` |
| `-b` | Target BSSID | `-b 00:90:4C:C1:AC:21` |
| `-B` | Enable bruteforce mode | `-B` |
| `-p` | PIN prefix for bruteforce | `-p 1234` |
| `-v` | Verbose output | `-v` |
| `-w` | Save credentials | `-w` |
| `-l` | Loop mode | `-l` |
| `-r` | Reverse scan order | `-r` |

## 🔍 Troubleshooting

### Common Issues

**"Device or resource busy (-16)"**
- **Solution**: Turn on WiFi, then turn it off again before running the tool

**Permission denied**
- **Solution**: Ensure you're running with `sudo` and have root access

**Network interface not found**
- **Solution**: Check available interfaces with `iwconfig` or `ip link show`

**wpa_supplicant errors**
- **Solution**: Ensure wpa_supplicant is compiled with WPS support

### Logging

The tool now generates detailed logs in `exwifi.log`:
- Error messages and stack traces
- Network scan results
- Attack progress and statistics
- Configuration changes

## 🛡️ Security Features

### Enhanced Validation
- MAC address format validation
- Input sanitization
- Error boundary protection
- Graceful failure handling

### Better Resource Management
- Automatic cleanup on exit
- Signal handling for graceful shutdown
- Memory leak prevention
- Temporary file management

## 📊 Performance Improvements

### Optimized Algorithms
- Enhanced WPS PIN generation
- Better bruteforce strategies
- Improved network scanning
- Faster session restoration

### Memory Management
- Efficient data structures
- Reduced memory footprint
- Better garbage collection
- Optimized string handling

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Guidelines
- Follow PEP 8 style guidelines
- Add type hints to new functions
- Include comprehensive error handling
- Write tests for new features
- Update documentation

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

## 🔄 Changelog

### Version 2024 (Enhanced Edition)
- ✨ Modern UI with color-coded output
- 🔧 Enhanced error handling and logging
- ⚙️ Configuration management system
- 📊 Progress tracking and status indicators
- 🛡️ Better security and validation
- 🚀 Performance optimizations
- 📝 Improved documentation

---

**Remember**: Always use this tool responsibly and only on networks you own or have permission to test.

**Stay With ErrorX** 🚀
