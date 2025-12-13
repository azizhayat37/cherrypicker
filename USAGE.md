# CherryPicker v2.0 - Bind Shell Architecture

ICMP-triggered reverse shell **replaced with** authenticated bind shell for authorized penetration testing.

## ⚠️ Legal Disclaimer

This tool is designed **exclusively for authorized penetration testing** and security research. Unauthorized use is **illegal**.

## Architecture Overview

**New design:**
- **Target module** - Runs on target, listens on a port
- **Attacker module** - Connects to target, establishes authenticated shell

```
┌─────────────┐              ┌──────────────┐
│ Attacker    │              │ Target       │
│             │              │              │
│ ./attacker  ├──────────────► :9999        │
│ -target IP  │   Connect    │ (listening)  │
│             │              │              │
│             ├──────────────► Auth         │
│             │   Challenge  │              │
│             │              │              │
│             ◄──────────────┤ Shell        │
│ Interactive │   If Valid   │              │
└─────────────┘              └──────────────┘
```

## Quick Start

### 1. Build Both Modules

```bash
# Build target module (to deploy)
cd target
go build -o cherrypicker-target

# Build attacker module (your machine)
cd ../attacker
go build -o cherrypicker-attacker
```

Or use cross-compilation:
```bash
# Linux target
cd target && GOOS=linux GOARCH=amd64 go build -o cherrypicker-target-linux

# Windows target
cd target && GOOS=windows GOARCH=amd64 go build -o cherrypicker-target.exe
```

### 2. Deploy Target Module

Copy `cherrypicker-target` to your authorized target system.

**Run on target:**
```bash
# Default port 9999, default key
./cherrypicker-target

# Custom port and authentication key
./cherrypicker-target -port 8888 -key "MySecretKey123"
```

**Important:** Target listens on **all interfaces** (0.0.0.0). Consider firewall rules.

### 3. Connect from Attacker

**On your attack machine:**
```bash
# Connect with default settings
./cherrypicker-attacker -target 192.168.1.50

# Custom port and key (must match target)
./cherrypicker-attacker -target 192.168.1.50 -port 8888 -key "MySecretKey123"

# Specify timeout
./cherrypicker-attacker -target 192.168.1.50 -timeout 30
```

You'll get an interactive shell if authentication succeeds.

## Authentication

Uses **challenge-response** to prevent unauthorized access:

1. Target generates random challenge
2. Target sends challenge to attacker
3. Attacker computes `SHA256(challenge + shared_key)`
4. Attacker sends response
5. Target verifies response
6. If valid, shell is spawned

**Both sides must use the same authentication key.**

## Command Line Options

### Target Module
```bash
-port <num>    Port to listen on (default: 9999)
-key <string>  Authentication key (default: "CHERRY_PICKER_2025")
```

### Attacker Module
```bash
-target <IP>     Target IP address (required)
-port <num>      Target port (default: 9999)
-key <string>    Authentication key (default: "CHERRY_PICKER_2025")
-timeout <sec>   Connection timeout (default: 10)
```

## Security Features

- ✅ Challenge-response authentication (SHA256)
- ✅ Prevents unauthorized shell access
- ✅ Configurable shared secrets
- ✅ Connection timeouts
- ✅ Authentication timeouts (10s)
- ✅ No hardcoded credentials in binary

## Usage Examples

### Basic Usage
```bash
# On target (192.168.1.50)
./cherrypicker-target

# On attacker
./cherrypicker-attacker -target 192.168.1.50
```

### Custom Configuration
```bash
# On target
./cherrypicker-target -port 31337 -key "Sup3rS3cr3t!"

# On attacker
./cherrypicker-attacker -target 192.168.1.50 -port 31337 -key "Sup3rS3cr3t!"
```

### IPv6 Support
```bash
./cherrypicker-attacker -target 2001:db8::1 -port 9999
```

## Building

```bash
# Install dependencies (if needed)
go mod tidy

# Build both modules
cd target && go build -o cherrypicker-target
cd ../attacker && go build -o cherrypicker-attacker

# Build for multiple platforms
cd target && GOOS=linux GOARCH=amd64 go build -o cherrypicker-target-linux
cd target && GOOS=windows GOARCH=amd64 go build -o cherrypicker-target.exe
```

## Differences from v1.0

| Feature | v1.0 (ICMP) | v2.0 (Bind Shell) |
|---------|-------------|-------------------|
| Trigger | ICMP magic ping | Direct TCP connection |
| Direction | Target → Attacker | Attacker → Target |
| Auth | Magic signature | Challenge-response |
| Network | Requires ICMP | Requires open port |
| Stealth | No open ports | Port listening |
| Complexity | High (raw sockets) | Low (standard TCP) |

## When to Use v2.0

- ✅ Direct network access to target
- ✅ Firewall allows inbound connections
- ✅ Simpler deployment preferred
- ✅ No need for root privileges (non-privileged ports)

## When to Use v1.0 (ICMP version)

- ✅ Target behind restrictive firewall
- ✅ Need maximum stealth (no open ports)
- ✅ ICMP is allowed but inbound TCP is not
- ✅ Want to avoid port scanning detection

## Troubleshooting

**Connection refused:**
- Verify target module is running
- Check firewall rules on target
- Verify IP and port are correct

**Authentication failed:**
- Ensure both sides use the same `-key`
- Keys are case-sensitive
- Check for typos

**Connection timeout:**
- Target may be unreachable
- Increase `-timeout` value
- Check network connectivity with `ping`

## Security Considerations

⚠️ **Change the default authentication key before deployment!**

- Use strong, random keys (minimum 20 characters)
- Consider using environment variables for keys
- Limit port exposure with firewall rules
- Monitor connection attempts
- Use non-standard ports to avoid scanning
- Consider adding IP whitelisting

## License

For authorized penetration testing use only. See LICENSE file.
