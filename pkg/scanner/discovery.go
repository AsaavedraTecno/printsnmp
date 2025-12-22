package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/asaavedra/agent-snmp/pkg/snmp"
)

// DiscoveryResult contiene información de un dispositivo descubierto
type DiscoveryResult struct {
	IP              string
	Community       string
	SNMPVersion     string
	SysDescr        string
	SysObjectID     string
	IsResponsive    bool
	ResponseTime    time.Duration
	DiscoveredAt    time.Time
	Brand           string
	BrandConfidence float64
	Errors          []string
}

// DiscoveryConfig contiene configuración para el discovery
type DiscoveryConfig struct {
	MaxConcurrentConnections int
	TimeoutPerDevice         time.Duration
	Retries                  int
	Community                string
	SNMPVersion              string
	SNMPPort                 uint16
}

// DiscoveryScanner ejecuta escaneo SNMP en paralelo
type DiscoveryScanner struct {
	config DiscoveryConfig
}

// NewDiscoveryScanner crea un nuevo scanner de discovery
func NewDiscoveryScanner(config DiscoveryConfig) *DiscoveryScanner {
	return &DiscoveryScanner{config: config}
}

// Scan ejecuta el escaneo de IPs
func (ds *DiscoveryScanner) Scan(ctx context.Context, ips []string) ([]DiscoveryResult, error) {
	results := make([]DiscoveryResult, 0, len(ips))
	resultsChan := make(chan DiscoveryResult, len(ips))
	var wg sync.WaitGroup

	// Semáforo para limitar concurrencia
	semaphore := make(chan struct{}, ds.config.MaxConcurrentConnections)

	fmt.Printf("Iniciando descubrimiento de %d IPs...\n", len(ips))
	startTime := time.Now()

	for _, ip := range ips {
		wg.Add(1)

		go func(targetIP string) {
			defer wg.Done()

			// Adquirir slot
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := ds.probeIP(ctx, targetIP)
			resultsChan <- result
		}(ip)
	}

	// Esperar a que todos terminen
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Recolectar resultados
	for result := range resultsChan {
		if result.IsResponsive {
			results = append(results, result)
		}
	}

	fmt.Printf("Descubrimiento completado en %.2f segundos. Encontradas %d impresoras.\n",
		time.Since(startTime).Seconds(), len(results))

	return results, nil
}

// probeIP prueba un IP individual
func (ds *DiscoveryScanner) probeIP(ctx context.Context, ip string) DiscoveryResult {
	result := DiscoveryResult{
		IP:           ip,
		Community:    ds.config.Community,
		SNMPVersion:  ds.config.SNMPVersion,
		DiscoveredAt: time.Now(),
	}

	startTime := time.Now()

	client := snmp.NewSNMPClient(
		ip,
		ds.config.SNMPPort,
		ds.config.Community,
		ds.config.SNMPVersion,
		ds.config.TimeoutPerDevice,
		ds.config.Retries,
	)

	// Intentar validar conexión
	err := client.ValidateConnection()
	if err != nil {
		result.IsResponsive = false
		result.Errors = append(result.Errors, fmt.Sprintf("validation_error: %v", err))
		return result
	}

	// Obtener sysDescr
	sysDescr, err := client.Get("1.3.6.1.2.1.1.1.0", snmp.NewContext())
	if err != nil {
		result.IsResponsive = false
		result.Errors = append(result.Errors, fmt.Sprintf("sysdescr_error: %v", err))
		return result
	}

	if sysDescr == nil || sysDescr == "" {
		result.IsResponsive = false
		result.Errors = append(result.Errors, "sysdescr_empty")
		return result
	}

	result.SysDescr = fmt.Sprintf("%v", sysDescr)

	// Obtener sysObjectID
	sysObjectID, err := client.Get("1.3.6.1.2.1.1.2.0", snmp.NewContext())
	if err == nil && sysObjectID != nil {
		result.SysObjectID = fmt.Sprintf("%v", sysObjectID)
	}

	result.IsResponsive = true
	result.ResponseTime = time.Since(startTime)

	// Detectar marca (será hecho después en el flujo principal)

	return result
}

// ScanAndIdentify ejecuta escaneo y detección de marca
func (ds *DiscoveryScanner) ScanAndIdentify(ctx context.Context, ips []string) ([]DiscoveryResult, error) {
	results, err := ds.Scan(ctx, ips)
	if err != nil {
		return nil, err
	}

	// Importar detector (evitar circular import)
	// Será hecho en el main

	return results, nil
}
