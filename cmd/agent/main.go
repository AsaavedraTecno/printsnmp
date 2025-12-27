package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/asaavedra/agent-snmp/pkg/collector"
	"github.com/asaavedra/agent-snmp/pkg/detector"
	"github.com/asaavedra/agent-snmp/pkg/scanner"
	"github.com/asaavedra/agent-snmp/pkg/serializer"
	"github.com/asaavedra/agent-snmp/pkg/sink"
	"github.com/asaavedra/agent-snmp/pkg/telemetry"
)

func main() {
	// Flags
	configFile := flag.String("config", "config.yaml", "Archivo de configuración")
	ipRangeOverride := flag.String("range", "", "Override del rango de IPs (ej: 192.168.1.1-254)")
	verbose := flag.Bool("verbose", false, "Modo verbose (override de config)")

	flag.Parse()

	// Cargar configuración desde YAML
	cfg, err := LoadConfig(*configFile)
	if err != nil {
		log.Printf("⚠️  No se pudo leer config.yaml: %v", err)
		cfg = DefaultConfig()
	}

	// Override con flags si se proporcionan
	if *ipRangeOverride != "" {
		cfg.Discovery.IPRange = *ipRangeOverride
	}
	if *verbose {
		cfg.Logging.Verbose = true
	}

	// Validar rango
	if cfg.Discovery.IPRange == "" {
		log.Fatalf("Error: Se requiere ip_range en config.yaml o -range en flags")
	}

	// Parsear rango de IPs
	ips, err := scanner.ParseIPRange(cfg.Discovery.IPRange)
	if err != nil {
		log.Fatalf("Error parseando rango: %v", err)
	}

	discoveryConfig := scanner.DiscoveryConfig{
		MaxConcurrentConnections: cfg.Discovery.MaxConcurrent,
		TimeoutPerDevice:         time.Duration(cfg.SNMP.TimeoutMs) * time.Millisecond,
		Retries:                  cfg.SNMP.Retries,
		Community:                cfg.SNMP.Community,
		SNMPVersion:              cfg.SNMP.Version,
		SNMPPort:                 cfg.SNMP.Port,
	}

	// Ejecutar discovery
	startTime := time.Now()
	ctx := context.Background()

	if cfg.Discovery.Enabled {
		discoveryScanner := scanner.NewDiscoveryScanner(discoveryConfig)
		discoveries, err := discoveryScanner.Scan(ctx, ips)
		if err != nil {
			log.Fatalf("Error during discovery: %v", err)
		}

		if len(discoveries) == 0 {
			log.Fatalf("No SNMP devices found in range")
		}
		processPrinters(ctx, cfg, discoveries, startTime)
	} else {
		log.Fatalf("Discovery disabled in config.yaml")
	}
}

func processPrinters(ctx context.Context, cfg Config, discoveries []scanner.DiscoveryResult, startTime time.Time) {

	// Detectar marca para cada dispositivo
	deviceInfos := make([]collector.DeviceInfo, 0, len(discoveries))

	for _, disc := range discoveries {
		brand := detector.DetectBrand(disc.SysDescr)
		confidence := detector.GetBrandConfidence(disc.SysDescr, brand)

		deviceInfo := collector.DeviceInfo{
			IP:              disc.IP,
			Brand:           brand,
			BrandConfidence: confidence,
			SysDescr:        disc.SysDescr,
			Community:       cfg.SNMP.Community,
			SNMPVersion:     cfg.SNMP.Version,
		}

		deviceInfos = append(deviceInfos, deviceInfo)
	}

	// Configurar colector de datos
	collectorConfig := collector.Config{
		Timeout:                  time.Duration(cfg.SNMP.TimeoutMs) * time.Millisecond,
		Retries:                  cfg.SNMP.Retries,
		MaxConcurrentConnections: cfg.Discovery.MaxConcurrent,
		MaxOidsPerDevice:         10,
		MinDelayBetweenQueries:   time.Duration(cfg.Collector.DelayMs) * time.Millisecond,
		Community:                cfg.SNMP.Community,
		SNMPVersion:              cfg.SNMP.Version,
		SNMPPort:                 cfg.SNMP.Port,
	}

	// Recolectar datos
	if cfg.Collector.Enabled {
		fmt.Printf("📊 Recolectando datos de impresoras...\n")
		dataCollector := collector.NewDataCollector(collectorConfig)
		printerDataList, err := dataCollector.CollectData(ctx, deviceInfos)
		if err != nil {
			log.Fatalf("Error recolectando datos: %v", err)
		}

		fmt.Printf("✓ Datos recolectados de %d impresoras\n\n", len(printerDataList))

		// ========== FLUJO NUEVO: TELEMETRY → SINK ==========

		// Crear AgentSource (quién envía)
		agentSource := telemetry.AgentSource{
			AgentID:  getAgentID(),         // Del entorno o generado
			Hostname: getHostname(),        // Detectado
			OS:       getOperatingSystem(), // Detectado
			Version:  "1.0.0",              // Versión del agente
		}

		// Crear builder, serializer y state manager
		builder := telemetry.NewBuilder(agentSource)
		ser := serializer.NewSerializer()
		stateManager := collector.NewStateManager("state") // Directorio para persistir estado

		// Crear file sink para buffer local (siempre disponible)
		fileSink, err := sink.NewFileSink(cfg.Sinks.File.Path)
		if err != nil {
			log.Fatalf("Failed to initialize file sink: %v", err)
		}
		defer fileSink.Close()

		// Estadísticas
		bufferedCount := 0

		// Procesar CADA impresora como UN evento atómico
		for _, printerData := range printerDataList {
			// 0. Cargar estado anterior y calcular delta
			var delta *collector.CountersDiff
			var resetDetected bool

			if len(printerData.NormalizedCounters) > 0 || len(printerData.Counters) > 0 {
				// Construir CountersInfo con valores actuales
				countersToUse := printerData.NormalizedCounters
				if len(countersToUse) == 0 {
					countersToUse = printerData.Counters
				}

				currentCounters := collector.CountersInfo{
					TotalPages: extractCounterInt64(countersToUse, "total_pages"),
					MonoPages:  extractCounterInt64(countersToUse, "mono_pages"),
					ColorPages: extractCounterInt64(countersToUse, "color_pages"),
					ScanPages:  extractCounterInt64(countersToUse, "scan_pages"),
					CopyPages:  extractCounterInt64(countersToUse, "copy_pages"),
					FaxPages:   extractCounterInt64(countersToUse, "fax_pages"),
				}

				// Calcular delta
				delta, resetDetected = stateManager.CalculateDelta(printerData.IP, currentCounters)

				// Guardar estado actual para el próximo poll
				if err := stateManager.SaveState(printerData.IP, currentCounters); err != nil {
					log.Printf("⚠️  Failed to save state for %s: %v", printerData.IP, err)
				}
			}

			// 1. Construir Telemetry
			telem, err := builder.Build(&printerData, delta, resetDetected)
			if err != nil {
				log.Printf("❌ Failed to build telemetry for %s: %v", printerData.IP, err)
				continue
			}

			// 2. Serializar a JSON
			jsonBytes, err := ser.Serialize(telem)
			if err != nil {
				log.Printf("❌ Failed to serialize telemetry for %s: %v", printerData.IP, err)
				continue
			}

			// 3. Enviar a sink (por ahora solo file sink, HTTP vendría aquí)
			// TODO: Integrar HTTPSink con reintentos
			err = fileSink.Write(ctx, jsonBytes, printerData.IP)
			if err != nil {
				log.Printf("❌ Failed to buffer telemetry for %s: %v", printerData.IP, err)
				continue
			}

			bufferedCount++
		}

		endTime := time.Now()
		log.Printf("✅ Scan completed in %.2f seconds. Devices: %d, Telemetry queued: %d", endTime.Sub(startTime).Seconds(), len(printerDataList), bufferedCount)
	} else {
		fmt.Println("❌ Collector deshabilitado en config.yaml")
		os.Exit(0)
	}
}

// getAgentID obtiene el ID del agente (env var o default)
func getAgentID() string {
	if id := os.Getenv("AGENT_ID"); id != "" {
		return id
	}
	return "AGT-LOCAL-001" // Default para desarrollo
}

// getHostname obtiene el hostname del servidor
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// getOperatingSystem retorna el SO
func getOperatingSystem() string {
	osType := os.Getenv("GOOS") // Go runtime
	if osType != "" {
		return osType
	}
	return "unknown"
}

// extractCounterInt64 extrae un valor contador y lo retorna como int64
func extractCounterInt64(counters map[string]interface{}, key string) int64 {
	if counters == nil {
		return 0
	}

	val, ok := counters[key]
	if !ok {
		return 0
	}

	switch v := val.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	case string:
		// Intentar parsear string a int
		var num int64
		fmt.Sscanf(v, "%d", &num)
		return num
	default:
		return 0
	}
}
