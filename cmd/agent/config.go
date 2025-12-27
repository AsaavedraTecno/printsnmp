package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config contiene la configuración global del agente SNMP
type Config struct {
	Mode string `yaml:"mode"` // standalone | cloud-sync

	// SNMP
	SNMP struct {
		Community string `yaml:"community"`
		Version   string `yaml:"version"`
		Port      uint16 `yaml:"port"`
		TimeoutMs int    `yaml:"timeout_ms"`
		Retries   int    `yaml:"retries"`
	} `yaml:"snmp"`

	// Discovery
	Discovery struct {
		Enabled       bool   `yaml:"enabled"`
		IPRange       string `yaml:"ip_range"`
		MaxConcurrent int    `yaml:"max_concurrent"`
	} `yaml:"discovery"`

	// Collector
	Collector struct {
		Enabled bool `yaml:"enabled"`
		DelayMs int  `yaml:"delay_ms"`
	} `yaml:"collector"`

	// Sinks
	Sinks struct {
		File struct {
			Enabled bool   `yaml:"enabled"`
			Path    string `yaml:"path"`
		} `yaml:"file"`
		HTTP struct {
			Enabled           bool   `yaml:"enabled"`
			Endpoint          string `yaml:"endpoint"`
			Retries           int    `yaml:"retries"`
			BackoffMaxSeconds int    `yaml:"backoff_max_seconds"`
		} `yaml:"http"`
	} `yaml:"sinks"`

	// Logging
	Logging struct {
		Verbose bool   `yaml:"verbose"`
		Level   string `yaml:"level"`
	} `yaml:"logging"`
}

// LoadConfig carga la configuración desde config.yaml
func LoadConfig(filePath string) (Config, error) {
	var cfg Config

	// Leer archivo
	data, err := os.ReadFile(filePath)
	if err != nil {
		return cfg, fmt.Errorf("error leyendo %s: %w", filePath, err)
	}

	// Parsear YAML
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("error parseando YAML: %w", err)
	}

	return cfg, nil
}

// DefaultConfig retorna la configuración por defecto
func DefaultConfig() Config {
	cfg := Config{
		Mode: "standalone",
	}
	cfg.SNMP.Community = "public"
	cfg.SNMP.Version = "2c"
	cfg.SNMP.Port = 161
	cfg.SNMP.TimeoutMs = 2000
	cfg.SNMP.Retries = 1
	cfg.Discovery.Enabled = true
	cfg.Discovery.MaxConcurrent = 10
	cfg.Collector.Enabled = true
	cfg.Collector.DelayMs = 50
	cfg.Sinks.File.Enabled = true
	cfg.Sinks.File.Path = "./queue"
	cfg.Sinks.HTTP.Enabled = false
	cfg.Logging.Verbose = true
	cfg.Logging.Level = "info"
	return cfg
}
