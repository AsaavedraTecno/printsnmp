package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asaavedra/agent-snmp/pkg/collector"
	"github.com/asaavedra/agent-snmp/pkg/normalizer"
)

// ScanSummary contiene el resumen del escaneo
type ScanSummary struct {
	ScanStartTime       time.Time      `json:"scanStartTime"`
	ScanEndTime         time.Time      `json:"scanEndTime"`
	ScanDuration        string         `json:"scanDuration"`
	Range               string         `json:"range"`
	TotalScanned        int            `json:"totalScanned"`
	TotalFound          int            `json:"totalFound"`
	TotalSuccessful     int            `json:"totalSuccessful"`
	CommunityString     string         `json:"communityString"`
	ByBrand             map[string]int `json:"byBrand"`
	HealthStats         *HealthStats   `json:"healthStats"`
	AverageResponseTime float64        `json:"avgResponseTimeMs"`
	SuccessRate         float64        `json:"successRate"`
}

// HealthStats contiene estadísticas de salud
type HealthStats struct {
	CriticalAlerts int `json:"criticalAlerts"`
	Warnings       int `json:"warnings"`
	Healthy        int `json:"healthy"`
}

// ScanOutput es el formato de salida JSON principal
type ScanOutput struct {
	ScanInfo *ScanSummary                    `json:"scanInfo"`
	Printers []*normalizer.NormalizedPrinter `json:"printers"`
}

// FrontendPrinter es una estructura optimizada para el frontend
type FrontendPrinter struct {
	ID              string                 `json:"id"`
	IP              string                 `json:"ip"`
	Brand           string                 `json:"brand"`
	BrandConfidence float64                `json:"brandConfidence"`
	Model           string                 `json:"model"`
	SerialNumber    string                 `json:"serialNumber"`
	Hostname        string                 `json:"hostname"`
	Location        string                 `json:"location,omitempty"`
	Status          string                 `json:"status"`
	TotalPages      int64                  `json:"totalPages"`
	Supplies        []SupplyInfo           `json:"supplies"`
	Counters        map[string]interface{} `json:"counters"`
	NetworkInfo     map[string]interface{} `json:"networkInfo"`
	AdminInfo       map[string]interface{} `json:"adminInfo,omitempty"`
	Timestamp       string                 `json:"timestamp"`
	ResponseTimeMs  int64                  `json:"responseTimeMs"`
	LastUpdate      string                 `json:"lastUpdate"`
	HealthScore     int                    `json:"healthScore"` // 0-100
}

// SupplyInfo contiene información de un consumible para frontend
type SupplyInfo struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"` // "toner", "ink", "drum", "fuser", etc
	Description string  `json:"description"`
	Level       int64   `json:"level"`
	Max         int64   `json:"max"`
	Percentage  float64 `json:"percentage"`
	Status      string  `json:"status"`    // OK, Bueno, Bajo, Crítico, Agotado
	NeedOrder   bool    `json:"needOrder"` // true si < 25%
}

// FrontendOutput es la salida optimizada para frontend
type FrontendOutput struct {
	Meta struct {
		Version       string         `json:"version"`
		ExportTime    string         `json:"exportTime"`
		TotalPrinters int            `json:"totalPrinters"`
		SuccessCount  int            `json:"successCount"`
		PartialCount  int            `json:"partialCount"`
		FailedCount   int            `json:"failedCount"`
		CriticalCount int            `json:"criticalCount"`
		HealthyCount  int            `json:"healthyCount"`
		ByBrand       map[string]int `json:"byBrand"`
		TotalPages    int64          `json:"totalPages"`
		AverageHealth int            `json:"averageHealth"`
	} `json:"meta"`
	Printers []FrontendPrinter `json:"printers"`
}

// JSONWriter escribe los resultados en formato JSON
type JSONWriter struct {
	outputDir string
}

// NewJSONWriter crea un nuevo escritor JSON
func NewJSONWriter(outputDir string) *JSONWriter {
	return &JSONWriter{outputDir: outputDir}
}

// WriteScanResults escribe los resultados del escaneo a archivos JSON
func (jw *JSONWriter) WriteScanResults(
	rawData []collector.PrinterData,
	ipRange string,
	totalScanned int,
	startTime time.Time,
	endTime time.Time,
	community string,
) error {
	// Crear directorio si no existe
	if err := os.MkdirAll(jw.outputDir, 0755); err != nil {
		return fmt.Errorf("error creando directorio de salida: %w", err)
	}

	// Normalizar datos
	normalizedPrinters := make([]*normalizer.NormalizedPrinter, len(rawData))
	for i, raw := range rawData {
		normalizedPrinters[i] = normalizer.Normalize(raw)
	}

	// Generar resumen
	summary := jw.generateSummary(normalizedPrinters, ipRange, totalScanned, startTime, endTime, community)

	// Crear salida principal
	output := &ScanOutput{
		ScanInfo: summary,
		Printers: normalizedPrinters,
	}

	// Escribir JSON principal
	outputPath := filepath.Join(jw.outputDir, "printers.json")
	if err := jw.writeJSON(output, outputPath); err != nil {
		return fmt.Errorf("error escribiendo printers.json: %w", err)
	}
	fmt.Printf("✓ Resultados guardados en: %s\n", outputPath)

	// Escribir resumen
	summaryPath := filepath.Join(jw.outputDir, "scan_summary.json")
	if err := jw.writeJSON(summary, summaryPath); err != nil {
		return fmt.Errorf("error escribiendo scan_summary.json: %w", err)
	}
	fmt.Printf("✓ Resumen guardado en: %s\n", summaryPath)

	// Escribir datos crudos (opcional)
	rawPath := filepath.Join(jw.outputDir, "printers_raw.json")
	if err := jw.writeJSON(rawData, rawPath); err != nil {
		return fmt.Errorf("error escribiendo printers_raw.json: %w", err)
	}
	fmt.Printf("✓ Datos crudos guardados en: %s\n", rawPath)

	return nil
}

// WriteNormalizedPrinters escribe datos normalizados a JSON
func (jw *JSONWriter) WriteNormalizedPrinters(
	normalizedPrinters []*normalizer.NormalizedPrinter,
	summary *ScanSummary,
) error {
	// Crear directorio si no existe
	if err := os.MkdirAll(jw.outputDir, 0755); err != nil {
		return fmt.Errorf("error creando directorio de salida: %w", err)
	}

	// Crear salida principal
	output := &ScanOutput{
		ScanInfo: summary,
		Printers: normalizedPrinters,
	}

	// Escribir JSON principal
	outputPath := filepath.Join(jw.outputDir, "printers.json")
	if err := jw.writeJSON(output, outputPath); err != nil {
		return fmt.Errorf("error escribiendo printers.json: %w", err)
	}
	fmt.Printf("✓ Resultados guardados en: %s\n", outputPath)

	// Escribir resumen
	summaryPath := filepath.Join(jw.outputDir, "scan_summary.json")
	if err := jw.writeJSON(summary, summaryPath); err != nil {
		return fmt.Errorf("error escribiendo scan_summary.json: %w", err)
	}
	fmt.Printf("✓ Resumen guardado en: %s\n", summaryPath)

	return nil
}

// generateSummary genera el resumen del escaneo
func (jw *JSONWriter) generateSummary(
	printers []*normalizer.NormalizedPrinter,
	ipRange string,
	totalScanned int,
	startTime time.Time,
	endTime time.Time,
	community string,
) *ScanSummary {
	summary := &ScanSummary{
		ScanStartTime:   startTime,
		ScanEndTime:     endTime,
		ScanDuration:    fmt.Sprintf("%.1fs", endTime.Sub(startTime).Seconds()),
		Range:           ipRange,
		TotalScanned:    totalScanned,
		TotalFound:      len(printers),
		TotalSuccessful: len(printers),
		CommunityString: community,
		ByBrand:         make(map[string]int),
		HealthStats:     &HealthStats{},
	}

	// Contar por marca
	for _, printer := range printers {
		summary.ByBrand[printer.Brand]++

		// Contar alertas de salud
		if printer.Supplies != nil {
			if printer.Supplies.TonerBlack != nil && printer.Supplies.TonerBlack.Status == "critical" {
				summary.HealthStats.CriticalAlerts++
			} else if printer.Supplies.TonerBlack != nil && printer.Supplies.TonerBlack.Status == "warning" {
				summary.HealthStats.Warnings++
			} else if printer.Supplies.TonerBlack != nil && printer.Supplies.TonerBlack.Status == "ok" {
				summary.HealthStats.Healthy++
			}
		}
	}

	// Calcular promedio de tiempo de respuesta
	if len(printers) > 0 {
		var totalResponseTime int64 = 0
		for _, printer := range printers {
			if printer.Metadata != nil {
				totalResponseTime += printer.Metadata.ResponseTimeMs
			}
		}
		summary.AverageResponseTime = float64(totalResponseTime) / float64(len(printers))
		summary.SuccessRate = (float64(len(printers)) / float64(totalScanned)) * 100.0
	}

	return summary
}

// writeJSON escribe un objeto a JSON
func (jw *JSONWriter) writeJSON(data interface{}, filePath string) error {
	// Usar encoder con SetEscapeHTML(false) para no escapar & como \u0026
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("error serializando JSON: %w", err)
	}

	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("error escribiendo archivo: %w", err)
	}

	return nil
}

// WriteReport escribe un reporte legible en texto
func (jw *JSONWriter) WriteReport(summary *ScanSummary, printers []*normalizer.NormalizedPrinter) error {
	reportPath := filepath.Join(jw.outputDir, "scan_report.txt")

	file, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("error creando reporte: %w", err)
	}
	defer file.Close()

	// Escribir encabezado
	fmt.Fprintf(file, "╔═══════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(file, "║         REPORTE DE ESCANEO SNMP DE IMPRESORAS                  ║\n")
	fmt.Fprintf(file, "╚═══════════════════════════════════════════════════════════════╝\n\n")

	// Escribir información del escaneo
	fmt.Fprintf(file, "📊 INFORMACIÓN DEL ESCANEO\n")
	fmt.Fprintf(file, "─────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(file, "Rango escaneado:       %s\n", summary.Range)
	fmt.Fprintf(file, "Total escaneado:       %d IPs\n", summary.TotalScanned)
	fmt.Fprintf(file, "Impresoras encontradas: %d\n", summary.TotalFound)
	fmt.Fprintf(file, "Tasa de éxito:         %.1f%%\n", summary.SuccessRate)
	fmt.Fprintf(file, "Tiempo de escaneo:     %s\n", summary.ScanDuration)
	fmt.Fprintf(file, "Inicio:                %s\n", summary.ScanStartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "Final:                 %s\n\n", summary.ScanEndTime.Format("2006-01-02 15:04:05"))

	// Contar por marca
	fmt.Fprintf(file, "📦 IMPRESORAS POR MARCA\n")
	fmt.Fprintf(file, "─────────────────────────────────────────────────────────────\n")
	for brand, count := range summary.ByBrand {
		fmt.Fprintf(file, "%-20s: %d\n", brand, count)
	}
	fmt.Fprintf(file, "\n")

	// Estadísticas de salud
	fmt.Fprintf(file, "🏥 ESTADO DE CONSUMIBLES\n")
	fmt.Fprintf(file, "─────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(file, "Saludables:      %d\n", summary.HealthStats.Healthy)
	fmt.Fprintf(file, "Advertencias:    %d\n", summary.HealthStats.Warnings)
	fmt.Fprintf(file, "Críticos:        %d\n\n", summary.HealthStats.CriticalAlerts)

	// Detalles de impresoras
	fmt.Fprintf(file, "📋 DETALLE DE IMPRESORAS\n")
	fmt.Fprintf(file, "─────────────────────────────────────────────────────────────\n")

	for i, printer := range printers {
		fmt.Fprintf(file, "\n[%d] %s - %s\n", i+1, printer.IP, printer.Brand)
		fmt.Fprintf(file, "    Confianza:       %.0f%%\n", printer.BrandConfidence*100)
		if printer.Metadata != nil {
			fmt.Fprintf(file, "    Tiempo respuesta: %dms\n", printer.Metadata.ResponseTimeMs)
		}

		if printer.Identification != nil {
			if printer.Identification.Model != nil {
				fmt.Fprintf(file, "    Modelo:         %s\n", printer.Identification.Model.Value)
			}
			if printer.Identification.SerialNumber != nil {
				fmt.Fprintf(file, "    Serial:         %s\n", printer.Identification.SerialNumber.Value)
			}
		}

		if printer.Counters != nil && printer.Counters.TotalPages != nil {
			fmt.Fprintf(file, "    Total páginas:  %d\n", printer.Counters.TotalPages.Value)
		}

		if len(printer.MissingSections) > 0 {
			fmt.Fprintf(file, "    ⚠️  Secciones faltantes: %v\n", printer.MissingSections)
		}
	}

	fmt.Printf("✓ Reporte guardado en: %s\n", reportPath)
	return nil
}

// WriteOptimizedForFrontend escribe datos optimizados para consumo desde frontend
func (jw *JSONWriter) WriteOptimizedForFrontend(rawData []collector.PrinterData) error {
	if err := os.MkdirAll(jw.outputDir, 0755); err != nil {
		return fmt.Errorf("error creando directorio: %w", err)
	}

	output := &FrontendOutput{
		Printers: make([]FrontendPrinter, 0),
	}

	output.Meta.Version = "1.0"
	output.Meta.ExportTime = time.Now().Format(time.RFC3339)
	output.Meta.ByBrand = make(map[string]int)
	output.Meta.TotalPages = 0
	totalHealth := 0

	for _, raw := range rawData {
		fp := jw.rawToFrontendPrinter(raw)
		output.Printers = append(output.Printers, fp)

		// Actualizar estadísticas
		output.Meta.TotalPrinters++
		output.Meta.ByBrand[raw.Brand]++
		output.Meta.TotalPages += int64(parsePageCount(raw))
		totalHealth += fp.HealthScore

		// Clasificar por estado
		if len(raw.Errors) == 0 && len(raw.MissingSections) == 0 {
			output.Meta.SuccessCount++
		} else if len(raw.MissingSections) > 0 {
			output.Meta.PartialCount++
		} else {
			output.Meta.FailedCount++
		}

		// Contar alertas críticas
		for _, supply := range fp.Supplies {
			if supply.Status == "Crítico" || supply.Status == "Agotado" {
				output.Meta.CriticalCount++
			}
		}

		if fp.HealthScore >= 80 {
			output.Meta.HealthyCount++
		}
	}

	// Calcular promedio de salud
	if len(output.Printers) > 0 {
		output.Meta.AverageHealth = totalHealth / len(output.Printers)
	}

	// Escribir archivo optimizado para frontend
	frontendPath := filepath.Join(jw.outputDir, "printers_frontend.json")
	if err := jw.writeJSON(output, frontendPath); err != nil {
		return fmt.Errorf("error escribiendo frontend JSON: %w", err)
	}
	fmt.Printf("✓ Datos optimizados guardados en: %s\n", frontendPath)

	return nil
}

// rawToFrontendPrinter convierte PrinterData a FrontendPrinter
func (jw *JSONWriter) rawToFrontendPrinter(raw collector.PrinterData) FrontendPrinter {
	// Generar ID único: brand-hostname-timestamp-sn
	var idBase string
	if host, ok := raw.Identification["hostname"].(string); ok && host != "" {
		idBase = host
	} else {
		idBase = raw.IP
	}
	if sn, ok := raw.Identification["serialNumber"].(string); ok && sn != "" {
		idBase = idBase + "-" + sn
	}

	fp := FrontendPrinter{
		ID:              idBase,
		IP:              raw.IP,
		Brand:           raw.Brand,
		BrandConfidence: raw.Confidence,
		Timestamp:       raw.Timestamp.Format(time.RFC3339),
		ResponseTimeMs:  raw.ResponseTime.Milliseconds(),
		LastUpdate:      time.Now().Format(time.RFC3339),
		Supplies:        make([]SupplyInfo, 0),
		Counters:        make(map[string]interface{}),
		NetworkInfo:     make(map[string]interface{}),
		AdminInfo:       raw.AdminInfo,
	}

	// Extender información de identificación
	if model, ok := raw.Identification["model"].(string); ok {
		fp.Model = model
	}
	if sn, ok := raw.Identification["serialNumber"].(string); ok {
		fp.SerialNumber = sn
	}
	if host, ok := raw.Identification["hostname"].(string); ok {
		fp.Hostname = host
	}

	// Estado - convertir códigos a estados legibles
	if status, ok := raw.Status["generalStatus"].(string); ok {
		fp.Status = jw.translateStatus(status)
	}

	// Páginas totales
	if totalPages, ok := raw.Counters["totalPages"].(string); ok {
		fmt.Sscanf(totalPages, "%d", &fp.TotalPages)
	}

	// Procesar consumibles normalizados
	healthScore := 100
	for name, supply := range raw.NormalizedSupplies {
		if supplyMap, ok := supply.(map[string]interface{}); ok {
			si := SupplyInfo{
				Name: jw.normalizeSupplyName(name),
				Type: jw.getSupplyType(name),
			}

			if desc, ok := supplyMap["description"].(string); ok {
				si.Description = desc
			}
			if level, ok := supplyMap["level"].(float64); ok {
				si.Level = int64(level)
			}
			if max, ok := supplyMap["max"].(float64); ok {
				si.Max = int64(max)
			}
			if pct, ok := supplyMap["percentage"].(string); ok {
				fmt.Sscanf(pct, "%f%%", &si.Percentage)
			}
			if status, ok := supplyMap["status"].(string); ok {
				si.Status = status
				si.NeedOrder = status == "Crítico" || status == "Agotado"

				// Ajustar salud
				switch status {
				case "OK":
					// OK, no afecta
				case "Bueno":
					healthScore -= 5
				case "Bajo":
					healthScore -= 15
				case "Crítico":
					healthScore -= 40
				case "Agotado":
					healthScore -= 50
				}
			}

			fp.Supplies = append(fp.Supplies, si)
		}
	}
	fp.HealthScore = healthScore
	if fp.HealthScore < 0 {
		fp.HealthScore = 0
	}

	// Copiar contadores normalizados
	if len(raw.NormalizedCounters) > 0 {
		for key, val := range raw.NormalizedCounters {
			fp.Counters[key] = val
		}
	}

	// Copiar info de red
	for key, val := range raw.NetworkInfo {
		fp.NetworkInfo[key] = val
	}

	return fp
}

// normalizeSupplyName convierte IDs a nombres legibles
func (jw *JSONWriter) normalizeSupplyName(id string) string {
	names := map[string]string{
		"tonerBlack":     "Tóner Negro",
		"tonerCyan":      "Tóner Cyan",
		"tonerMagenta":   "Tóner Magenta",
		"tonerYellow":    "Tóner Amarillo",
		"fusor":          "Fusor",
		"drum":           "Tambor",
		"belt":           "Correa de Transferencia",
		"wasteContainer": "Contenedor de Residuos",
		"roller":         "Rodillo",
		"transferRoller": "Rodillo de Transferencia",
	}

	if name, ok := names[id]; ok {
		return name
	}
	return id
}

// getSupplyType clasifica el tipo de consumible
func (jw *JSONWriter) getSupplyType(name string) string {
	switch {
	case strings.Contains(strings.ToLower(name), "toner"), strings.Contains(strings.ToLower(name), "ink"):
		return "toner"
	case strings.Contains(strings.ToLower(name), "drum"):
		return "drum"
	case strings.Contains(strings.ToLower(name), "fuser"):
		return "fuser"
	case strings.Contains(strings.ToLower(name), "roller"), strings.Contains(strings.ToLower(name), "transfer"):
		return "roller"
	case strings.Contains(strings.ToLower(name), "waste"):
		return "waste"
	default:
		return "other"
	}
}

// parsePageCount extrae el contador de páginas totales
func parsePageCount(raw collector.PrinterData) int64 {
	if totalPages, ok := raw.Counters["totalPages"].(string); ok {
		var count int64
		fmt.Sscanf(totalPages, "%d", &count)
		return count
	}
	return 0
}

// translateStatus convierte códigos de estado SNMP a palabras legibles
func (jw *JSONWriter) translateStatus(status string) string {
	statusMap := map[string]string{
		"idle":    "inactivo",     // Esperando trabajo
		"ready":   "listo",        // Listo para imprimir
		"busy":    "ocupado",      // Imprimiendo/procesando
		"error":   "error",        // Hay un error
		"offline": "desconectado", // No disponible
		"other":   "otro",
		"1":       "otro",
		"2":       "inactivo",
		"3":       "listo",
		"4":       "error",
		"5":       "desconectado",
		"6":       "ocupado",
	}

	if translated, ok := statusMap[strings.ToLower(status)]; ok {
		return translated
	}
	return status // Retornar original si no se reconoce
}
