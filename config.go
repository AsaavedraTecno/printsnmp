package main

import (
	"time"
)

// Config contiene la configuración global del agente SNMP
type Config struct {
	// SNMP
	Community   string
	SNMPVersion string
	SNMPPort    uint16
	Timeout     time.Duration
	Retries     int

	// Rate Limiting
	MaxConcurrentConnections int
	MaxOidsPerDevice         int
	MinDelayBetweenQueries   time.Duration

	// Output
	OutputDir string
}

// DefaultConfig retorna la configuración por defecto
func DefaultConfig() Config {
	return Config{
		Community:                "public",
		SNMPVersion:              "2c",
		SNMPPort:                 161,
		Timeout:                  2 * time.Second,
		Retries:                  1,
		MaxConcurrentConnections: 10,
		MaxOidsPerDevice:         10,
		MinDelayBetweenQueries:   50 * time.Millisecond,
		OutputDir:                "./output",
	}
}
