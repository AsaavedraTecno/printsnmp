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
	"github.com/asaavedra/agent-snmp/pkg/output"
	"github.com/asaavedra/agent-snmp/pkg/scanner"
)

func main() {
	// Flags
	ipRangeFlag := flag.String("range", "", "Rango de IPs a escanear (ej: 192.168.1.1-254)")
	communityFlag := flag.String("community", "public", "Comunidad SNMP")
	versionFlag := flag.String("version", "2c", "Versión SNMP (1 o 2c)")
	portFlag := flag.Int("port", 161, "Puerto SNMP")
	timeoutFlag := flag.Duration("timeout", 2*time.Second, "Timeout SNMP")
	outputDirFlag := flag.String("output", "./output", "Directorio de salida")
	maxConcurrentFlag := flag.Int("concurrent", 10, "Máximo de conexiones concurrentes")
	verbose := flag.Bool("verbose", false, "Modo verbose")

	flag.Parse()

	// Validar rango
	if *ipRangeFlag == "" {
		fmt.Println("❌ Error: Se requiere el parámetro -range")
		fmt.Println("\nUso:")
		fmt.Println("  agent-snmp -range 192.168.1.1-254")
		fmt.Println("\nOpciones:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Parsear rango de IPs
	fmt.Printf("🔍 Parseando rango de IPs: %s\n", *ipRangeFlag)
	ips, err := scanner.ParseIPRange(*ipRangeFlag)
	if err != nil {
		fmt.Printf("❌ Error parseando rango: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Se escaneará un total de %d IPs\n\n", len(ips))

	// Configurar scanner de discovery
	discoveryConfig := scanner.DiscoveryConfig{
		MaxConcurrentConnections: *maxConcurrentFlag,
		TimeoutPerDevice:         *timeoutFlag,
		Retries:                  1,
		Community:                *communityFlag,
		SNMPVersion:              *versionFlag,
		SNMPPort:                 uint16(*portFlag),
	}

	// Ejecutar discovery
	startTime := time.Now()
	ctx := context.Background()

	discoveryScanner := scanner.NewDiscoveryScanner(discoveryConfig)
	discoveries, err := discoveryScanner.Scan(ctx, ips)
	if err != nil {
		log.Fatalf("Error durante discovery: %v", err)
	}

	if len(discoveries) == 0 {
		fmt.Println("❌ No se encontraron dispositivos SNMP en el rango especificado")
		os.Exit(0)
	}

	// Detectar marca para cada dispositivo
	fmt.Printf("\n🏢 Identificando marcas de impresoras...\n")
	deviceInfos := make([]collector.DeviceInfo, 0, len(discoveries))

	for i, disc := range discoveries {
		brand := detector.DetectBrand(disc.SysDescr)
		confidence := detector.GetBrandConfidence(disc.SysDescr, brand)

		deviceInfo := collector.DeviceInfo{
			IP:              disc.IP,
			Brand:           brand,
			BrandConfidence: confidence,
			SysDescr:        disc.SysDescr,
			Community:       discoveryConfig.Community,
			SNMPVersion:     discoveryConfig.SNMPVersion,
		}

		deviceInfos = append(deviceInfos, deviceInfo)

		if *verbose {
			fmt.Printf("[%d/%d] %s -> %s (confianza: %.0f%%)\n",
				i+1, len(discoveries), disc.IP, brand, confidence*100)
		}
	}

	fmt.Printf("✓ Se identificaron %d marcas\n\n", len(deviceInfos))

	// Configurar colector de datos
	collectorConfig := collector.Config{
		Timeout:                  *timeoutFlag,
		Retries:                  1,
		MaxConcurrentConnections: *maxConcurrentFlag,
		MaxOidsPerDevice:         10,
		MinDelayBetweenQueries:   50 * time.Millisecond,
		Community:                *communityFlag,
		SNMPVersion:              *versionFlag,
		SNMPPort:                 uint16(*portFlag),
	}

	// Recolectar datos
	fmt.Printf("📊 Recolectando datos de impresoras...\n")
	dataCollector := collector.NewDataCollector(collectorConfig)
	printerDataList, err := dataCollector.CollectData(ctx, deviceInfos)
	if err != nil {
		log.Fatalf("Error recolectando datos: %v", err)
	}

	fmt.Printf("✓ Datos recolectados de %d impresoras\n\n", len(printerDataList))

	// Escribir salida JSON
	endTime := time.Now()
	fmt.Printf("💾 Escribiendo salida JSON...\n")
	jsonWriter := output.NewJSONWriter(*outputDirFlag)

	// Escribir SOLO los JSONs necesarios:
	// 1. Crudo (printers_raw.json)
	err = jsonWriter.WriteScanResults(
		printerDataList,
		*ipRangeFlag,
		len(ips),
		startTime,
		endTime,
		*communityFlag,
	)
	if err != nil {
		log.Fatalf("Error escribiendo salida: %v", err)
	}

	// 2. Normalizado para frontend (printers_frontend.json)
	err = jsonWriter.WriteOptimizedForFrontend(printerDataList)
	if err != nil {
		log.Fatalf("Error escribiendo JSON optimizado: %v", err)
	}

	fmt.Printf("\n✅ ESCANEO COMPLETADO\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("Tiempo total:          %.2f segundos\n", endTime.Sub(startTime).Seconds())
	fmt.Printf("IPs escaneadas:        %d\n", len(ips))
	fmt.Printf("Impresoras encontradas: %d\n", len(printerDataList))
	fmt.Printf("Tasa de éxito:         %.1f%%\n", float64(len(printerDataList))/float64(len(ips))*100)
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")

	// Calcular estadísticas por marca
	byBrand := make(map[string]int)
	for _, pd := range printerDataList {
		byBrand[pd.Brand]++
	}

	fmt.Printf("📦 Impresoras por marca:\n")
	for brand, count := range byBrand {
		fmt.Printf("   %-20s: %d\n", brand, count)
	}

	fmt.Printf("\n📂 Archivos generados en: %s\n", *outputDirFlag)
	fmt.Printf("   • printers_frontend.json   ✅ USAR ESTE - Normalizado para frontend/nube\n")
	fmt.Printf("   • printers_raw.json        📊 Datos crudos del SNMP (backup)\n")
}
