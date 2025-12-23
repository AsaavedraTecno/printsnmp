package collector

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/asaavedra/agent-snmp/pkg/oids"
	"github.com/asaavedra/agent-snmp/pkg/snmp"
)

// PrinterData contiene toda la información recolectada de una impresora
type PrinterData struct {
	IP              string                 `json:"ip"`
	Brand           string                 `json:"brand"`
	Confidence      float64                `json:"confidence"`
	Identification  map[string]interface{} `json:"identification"`
	Status          map[string]interface{} `json:"status"`
	Supplies        map[string]interface{} `json:"supplies"`
	Counters        map[string]interface{} `json:"counters"`
	Trays           map[string]interface{} `json:"trays"`
	NetworkInfo     map[string]interface{} `json:"networkInfo"`
	AdminInfo       map[string]interface{} `json:"adminInfo"`
	Errors          []string               `json:"errors"`
	MissingSections []string               `json:"missingSections"`
	Timestamp       time.Time              `json:"timestamp"`
	ResponseTime    time.Duration          `json:"responseTime"`
	ProbeAttempts   int                    `json:"probeAttempts"`
	// Datos normalizados para presentación legible
	NormalizedSupplies map[string]interface{} `json:"normalizedSupplies"`
	NormalizedCounters map[string]interface{} `json:"normalizedCounters"`
}

// DeviceInfo contiene información sobre un dispositivo a procesar
type DeviceInfo struct {
	IP              string
	Brand           string
	BrandConfidence float64
	SysDescr        string
	Community       string
	SNMPVersion     string
}

// DataCollector recolecta datos de impresoras
type DataCollector struct {
	config      Config
	rateLimiter *RateLimiter
}

// Config contiene configuración del colector
type Config struct {
	Timeout                  time.Duration
	Retries                  int
	MaxConcurrentConnections int
	MaxOidsPerDevice         int
	MinDelayBetweenQueries   time.Duration
	Community                string
	SNMPVersion              string
	SNMPPort                 uint16
}

// NewDataCollector crea un nuevo colector de datos
func NewDataCollector(config Config) *DataCollector {
	return &DataCollector{
		config:      config,
		rateLimiter: NewRateLimiter(config.MaxConcurrentConnections),
	}
}

// CollectData recolecta datos de múltiples IPs
func (dc *DataCollector) CollectData(ctx context.Context, devices []DeviceInfo) ([]PrinterData, error) {
	results := make([]PrinterData, 0, len(devices))
	resultsChan := make(chan PrinterData, len(devices))
	var wg sync.WaitGroup

	fmt.Printf("Iniciando recolección de datos de %d dispositivos...\n", len(devices))
	startTime := time.Now()

	for _, device := range devices {
		wg.Add(1)

		go func(devInfo DeviceInfo) {
			defer wg.Done()

			// Usar rate limiter
			dc.rateLimiter.Wait()
			defer dc.rateLimiter.Release()

			data := dc.collectFromDevice(ctx, devInfo)
			resultsChan <- data
		}(device)
	}

	// Esperar a que todos terminen
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Recolectar resultados
	for data := range resultsChan {
		results = append(results, data)
	}

	fmt.Printf("Recolección completada en %.2f segundos.\n", time.Since(startTime).Seconds())

	return results, nil
}

// collectFromDevice recolecta datos de un dispositivo específico
func (dc *DataCollector) collectFromDevice(ctx context.Context, device DeviceInfo) PrinterData {
	startTime := time.Now()

	data := PrinterData{
		IP:                 device.IP,
		Brand:              device.Brand,
		Confidence:         device.BrandConfidence,
		Identification:     make(map[string]interface{}),
		Status:             make(map[string]interface{}),
		Supplies:           make(map[string]interface{}),
		Counters:           make(map[string]interface{}),
		Trays:              make(map[string]interface{}),
		NetworkInfo:        make(map[string]interface{}),
		AdminInfo:          make(map[string]interface{}),
		Errors:             make([]string, 0),
		MissingSections:    make([]string, 0),
		Timestamp:          time.Now(),
		NormalizedSupplies: make(map[string]interface{}),
		NormalizedCounters: make(map[string]interface{}),
	}

	// Crear cliente SNMP
	client := snmp.NewSNMPClient(
		device.IP,
		dc.config.SNMPPort,
		device.Community,
		device.SNMPVersion,
		dc.config.Timeout,
		dc.config.Retries,
	)

	// Recolectar identificación básica
	dc.collectIdentification(client, &data)

	// Recolectar estado de la impresora
	dc.collectStatus(client, &data)

	// Recolectar consumibles dinámicamente vía WALK
	walkCtx := snmp.NewContext()
	consumiblesViaWalk, walkErr := dc.CollectConsumiblesViaWalk(client, walkCtx)
	if walkErr == nil && len(consumiblesViaWalk) > 0 {
		// Merge con supplies existentes
		for key, val := range consumiblesViaWalk {
			if _, exists := data.Supplies[key]; !exists {
				data.Supplies[key] = val
			}
		}
	}

	// Recolectar contadores de páginas
	dc.collectCounters(client, &data)

	// Recolectar información de energía
	dc.collectPowerInfo(client, &data)

	// Recolectar información de bandejas
	dc.collectTraysInfo(client, &data)

	// Recolectar información de red
	dc.collectNetworkInfo(client, &data)

	// Recolectar información administrativa (ubicación, contacto, uptime)
	dc.collectAdminInfo(client, &data)

	// Descobrir datos adicionales mediante WALK exhaustivo
	dc.discoverAdditionalData(client, &data)

	// Extraer ubicación de los datos descubiertos (si no fue capturada directamente)
	dc.extractLocationFromDiscovered(&data)

	// DESPUÉS de descubrir datos, extraer contadores de página que están en la sección supplies (Xerox, Samsung, etc)
	dc.extractPageCountersFromSupplies(&data)

	data.ResponseTime = time.Since(startTime)
	data.ProbeAttempts = 1

	// Normalizar y procesar datos para presentación legible
	dc.normalizeData(&data)

	// Contar secciones vacías
	if len(data.Status) == 0 {
		data.MissingSections = append(data.MissingSections, "status")
	}
	if len(data.Supplies) == 0 {
		data.MissingSections = append(data.MissingSections, "supplies")
	}
	if len(data.Counters) == 0 {
		data.MissingSections = append(data.MissingSections, "counters")
	}

	return data
}

// CollectConsumiblesViaWalk descubre consumibles mediante SNMP WALK dinámico
func (dc *DataCollector) CollectConsumiblesViaWalk(client *snmp.SNMPClient, ctx *snmp.Context) (map[string]interface{}, error) {
	consumibles := make(map[string]interface{})

	// WALK 1: Obtener descripciones
	resultsDesc, err := client.Walk(oids.ConsumablesDesc, ctx)
	if err != nil {
		return consumibles, fmt.Errorf("error en WALK de descripciones: %w", err)
	}

	// WALK 2: Obtener niveles actuales
	resultsLevel, err := client.Walk(oids.ConsumablesLevel, ctx)
	if err != nil {
		resultsLevel = []snmp.WalkResult{}
	}

	// WALK 3: Obtener máximos
	resultsMax, err := client.Walk(oids.ConsumablesMax, ctx)
	if err != nil {
		resultsMax = []snmp.WalkResult{}
	}

	// Mapeo de descripciones a nombres normalizados
	consumibleMapping := map[string]string{
		"black toner":     "tonerBlack",
		"cyan toner":      "tonerCyan",
		"magenta toner":   "tonerMagenta",
		"yellow toner":    "tonerYellow",
		"black drum":      "drumBlack",
		"cyan drum":       "drumCyan",
		"magenta drum":    "drumMagenta",
		"yellow drum":     "drumYellow",
		"fuser":           "fusor",
		"transfer roller": "transferRoller",
		"waste toner":     "cajaResiduos",
		"waste container": "cajaResiduos",
		"adf roller":      "adfRoller",
		"retard roller":   "retardPad",
	}

	// Construir índice de niveles y máximos
	levelMap := make(map[string]string)
	maxMap := make(map[string]string)

	for _, result := range resultsLevel {
		levelMap[result.OID] = result.Value
	}
	for _, result := range resultsMax {
		maxMap[result.OID] = result.Value
	}

	// Procesar resultados de descripciones
	var oidsToGet []string
	indexMap := make(map[string]string) // Mapea levelOID a index

	for _, result := range resultsDesc {
		descValue := result.Value
		if descValue == "" {
			continue
		}

		// Extraer índice del OID (eliminar punto inicial si existe)
		oidStr := strings.TrimPrefix(result.OID, ".")

		parts := strings.Split(oidStr, ".")
		if len(parts) == 0 {
			continue
		}
		index := parts[len(parts)-1]

		// Normalizar descripción
		normalizedKey := ""
		for desc, key := range consumibleMapping {
			if len(descValue) > len(desc) && strings.Contains(strings.ToLower(descValue), strings.ToLower(desc)) {
				normalizedKey = key
				break
			}
		}

		if normalizedKey != "" {
			// Construir OIDs de nivel y máximo
			levelOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.9.1.%s", index)
			maxOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.8.1.%s", index)

			// Agregar a lista de OIDs a obtener
			oidsToGet = append(oidsToGet, levelOID, maxOID)
			indexMap[levelOID] = index
			indexMap[maxOID] = index
		}
	}

	// Hacer GET directo a los OIDs de level y max
	getCtx := snmp.NewContext()
	directValues, getErr := client.GetMultiple(oidsToGet, getCtx)

	// Procesar descripciones nuevamente con valores obtenidos
	for _, result := range resultsDesc {
		descValue := result.Value
		if descValue == "" {
			continue
		}

		// Extraer índice del OID
		oidStr := strings.TrimPrefix(result.OID, ".")

		parts := strings.Split(oidStr, ".")
		if len(parts) == 0 {
			continue
		}
		index := parts[len(parts)-1]

		// Normalizar descripción
		normalizedKey := ""
		for desc, key := range consumibleMapping {
			if len(descValue) > len(desc) && strings.Contains(strings.ToLower(descValue), strings.ToLower(desc)) {
				normalizedKey = key
				break
			}
		}

		if normalizedKey != "" {
			levelOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.9.1.%s", index)
			maxOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.8.1.%s", index)

			// Obtener valores del GET directo o del WALK
			levelVal := ""
			maxVal := ""

			if getErr == nil && directValues != nil {
				if val, ok := directValues[levelOID]; ok && val != nil {
					levelVal = fmt.Sprintf("%v", val)
				}
				if val, ok := directValues[maxOID]; ok && val != nil {
					maxVal = fmt.Sprintf("%v", val)
				}
			}

			// Fallback a valores del WALK si no se obtuvieron via GET
			if levelVal == "" {
				levelVal = levelMap[levelOID]
			}
			if maxVal == "" {
				maxVal = maxMap[maxOID]
			}

			consumibles[normalizedKey] = map[string]interface{}{
				"description": descValue,
				"oid_desc":    oidStr,
				"oid_level":   levelOID,
				"oid_max":     maxOID,
				"level":       levelVal,
				"max":         maxVal,
			}
		}
	}

	return consumibles, nil
}

// collectIdentification obtiene información de identificación del dispositivo
func (dc *DataCollector) collectIdentification(client *snmp.SNMPClient, data *PrinterData) {
	ctx := snmp.NewContext()

	// OIDs estándar de identificación
	oidList := []string{
		oids.SysDescr,
		oids.Model,
		oids.SerialNumber,
		oids.FirmwareVersion,
		oids.Hostname,
	}

	values, err := client.GetMultiple(oidList, ctx)
	if err != nil {
		return
	}

	// Mapeo de OID a nombre de campo
	oidMap := map[string]string{
		oids.SysDescr:        "sysDescr",
		oids.Model:           "model",
		oids.SerialNumber:    "serialNumber",
		oids.FirmwareVersion: "firmwareVersion",
		oids.Hostname:        "hostname",
	}

	for oid, fieldName := range oidMap {
		if val, exists := values[oid]; exists && val != nil && val != "" {
			data.Identification[fieldName] = sanitizeNetworkValue(val)
		}
	}
}

// collectStatus obtiene el estado de la impresora
func (dc *DataCollector) collectStatus(client *snmp.SNMPClient, data *PrinterData) {
	ctx := snmp.NewContext()

	// OIDs de estado
	statusOIDs := []string{
		oids.GeneralStatus,
		"1.3.6.1.4.1.253.8.53.4.2.1",
		"1.3.6.1.2.1.43.11.1.1.1",
		"1.3.6.1.2.1.43.11.1.1.10.1.1",
	}

	values, err := client.GetMultiple(statusOIDs, ctx)
	if err != nil {
		return
	}

	if val, exists := values[oids.GeneralStatus]; exists && val != nil && val != "" {
		// Decodificar estado numérico
		var statusText string
		valStr := fmt.Sprintf("%v", val)
		switch valStr {
		case "1":
			statusText = "other"
		case "2":
			statusText = "idle"
		case "3":
			statusText = "ready"
		case "4":
			statusText = "error"
		case "5":
			statusText = "offline"
		case "6":
			statusText = "busy"
		default:
			statusText = valStr
		}
		data.Status["generalStatus"] = statusText
	}
}

// collectCounters obtiene contadores de páginas impresas
func (dc *DataCollector) collectCounters(client *snmp.SNMPClient, data *PrinterData) {
	ctx := snmp.NewContext()

	// Usar OIDs centralizados
	counterOIDs := oids.OIDsContadoresDirectos
	oidList := oids.ExtractOIDs(counterOIDs)

	values, err := client.GetMultiple(oidList, ctx)
	if err == nil {
		for _, c := range counterOIDs {
			if val, exists := values[c.OID]; exists && val != nil && val != "" {
				valStr := fmt.Sprintf("%v", val)
				// Filtrar valores inválidos
				if !strings.HasPrefix(valStr, "-") && valStr != "0" {
					data.Counters[c.Nombre] = valStr
				}
			}
		}
	}

	// WALK exhaustivo del árbol de contadores estándar RFC 3805
	walkCtx := snmp.NewContext()
	baseOIDCounters := oids.PageCountersBase
	walkResults, err := client.Walk(baseOIDCounters, walkCtx)
	if err == nil {
		for _, result := range walkResults {
			if result.Value != "" && !strings.HasPrefix(result.Value, "-") && result.Value != "0" {
				// Guardar con clave que incluya el OID para que normalizeCounters lo identifique
				key := fmt.Sprintf("pageCounters__%s", result.OID)
				if _, exists := data.Counters[key]; !exists {
					data.Counters[key] = result.Value
				}
			}
		}
	}

	// WALK en OIDs de fabricantes específicos
	vendorWalks := oids.OIDsWalkFabricante

	for _, vwalk := range vendorWalks {
		vendorCtx := snmp.NewContext()
		vendorResults, err := client.Walk(vwalk.OID, vendorCtx)
		if err == nil {
			for _, result := range vendorResults {
				if result.Value != "" && !strings.HasPrefix(result.Value, "-") && result.Value != "0" {
					// Buscar patrones que indiquen contadores grandes
					if match, _ := regexp.MatchString(`\d{3,}`, result.Value); match {
						// Buscar OIDs que sugieran color o B&N
						if strings.Contains(strings.ToLower(result.OID), "color") ||
							strings.Contains(strings.ToLower(result.OID), "black") ||
							strings.Contains(strings.ToLower(result.OID), "mono") ||
							strings.Contains(strings.ToLower(result.OID), "bw") ||
							strings.HasSuffix(result.OID, ".2") || // segundo índice típicamente mono
							strings.HasSuffix(result.OID, ".3") { // tercer índice típicamente color

							key := fmt.Sprintf("%s_%s", vwalk.Prefijo, strings.ReplaceAll(result.OID, ".", "_"))
							// Evitar duplicados y priorizar valores ya encontrados
							if _, exists := data.Counters[key]; !exists {
								data.Counters[key] = result.Value
							}
						}
					}
				}
			}
		}
	}
}

// extractPageCountersFromSupplies extrae contadores de página color/BN de la sección supplies
// Algunos fabricantes (Xerox, Samsung, etc.) reportan contadores en OIDs de supplies
func (dc *DataCollector) extractPageCountersFromSupplies(data *PrinterData) {
	if data.Supplies == nil {
		return
	}

	// Mapeo de OIDs Xerox que contienen contadores de página disfrazados de supplies
	// Usan UN guión bajo entre el prefijo y el OID: xeroxSupplies_1_3_6_1_... (no __doble__)
	xeroxPageCounterOIDs := map[string]string{
		// OID: 1.3.6.1.4.1.253.8.53.13.2.1.2.1.20.29 = Color Printed Impressions
		"xeroxSupplies_1_3_6_1_4_1_253_8_53_13_2_1_2_1_20_29": "colorPages",
		// OID: 1.3.6.1.4.1.253.8.53.13.2.1.2.1.20.7 = Black Printed Impressions
		"xeroxSupplies_1_3_6_1_4_1_253_8_53_13_2_1_2_1_20_7": "monochromedPages",
		// OID: 1.3.6.1.4.1.253.8.53.13.2.1.2.1.20.1 = Total Impressions
		"xeroxSupplies_1_3_6_1_4_1_253_8_53_13_2_1_2_1_20_1": "totalPages",
	}

	// Samsung page counter OIDs en supplies
	samsungPageCounterOIDs := map[string]string{
		// Algunas Samsung reportan contadores en OIDs específicos
		"samsungSupplies_1_3_6_1_4_1_236_11_5_11_26_1_1_2_0": "totalPages",
		"samsungSupplies_1_3_6_1_4_1_236_11_5_11_26_1_1_3_0": "colorPages",
	}

	// Procesar OIDs Xerox
	for oid, counterName := range xeroxPageCounterOIDs {
		if val, exists := data.Supplies[oid]; exists {
			valStr := fmt.Sprintf("%v", val)
			// Filtrar valores inválidos
			if !strings.HasPrefix(valStr, "-") && valStr != "0" {
				data.Counters[counterName] = valStr
			}
		}
	}

	// Procesar OIDs Samsung
	for oid, counterName := range samsungPageCounterOIDs {
		if val, exists := data.Supplies[oid]; exists {
			valStr := fmt.Sprintf("%v", val)
			// Filtrar valores inválidos
			if !strings.HasPrefix(valStr, "-") && valStr != "0" {
				data.Counters[counterName] = valStr
			}
		}
	}
}

// collectPowerInfo obtiene información de energía y estado
func (dc *DataCollector) collectPowerInfo(client *snmp.SNMPClient, data *PrinterData) {
	ctx := snmp.NewContext()

	// OIDs de energía y estado extendido
	powerOIDs := []struct {
		name string
		oid  string
	}{
		{"powerState", "1.3.6.1.4.1.1602.1.2.1.1.1"},
		{"inputTrayStatus", "1.3.6.1.2.1.43.8.2.1.9.1.1"},
		{"outputTrayStatus", "1.3.6.1.2.1.43.9.2.1.9.1.1"},
		{"doorStatus", "1.3.6.1.4.1.253.8.53.4.2.2"},
		{"errorStatus", "1.3.6.1.4.1.253.8.53.4.2.3"},
	}

	oidList := make([]string, len(powerOIDs))
	for i, p := range powerOIDs {
		oidList[i] = p.oid
	}

	values, err := client.GetMultiple(oidList, ctx)
	if err != nil {
		return
	}

	for _, p := range powerOIDs {
		if val, exists := values[p.oid]; exists && val != nil && val != "" {
			data.Status[p.name] = fmt.Sprintf("%v", val)
		}
	}

	// También guardar info de energía en trays si es relevante
	if val, exists := values["1.3.6.1.2.1.43.8.2.1.9.1.1"]; exists && val != nil {
		data.Trays["inputTrayLevel"] = fmt.Sprintf("%v", val)
	}
}

// collectTraysInfo obtiene información detallada de bandejas
func (dc *DataCollector) collectTraysInfo(client *snmp.SNMPClient, data *PrinterData) {
	ctx := snmp.NewContext()

	// WALK exhaustivo de bandejas de entrada
	baseOIDInput := "1.3.6.1.2.1.43.8.2.1"
	results, err := client.Walk(baseOIDInput, ctx)
	if err == nil {
		for _, result := range results {
			if result.Value != "" && result.Value != "0" {
				parts := strings.Split(result.OID, ".")
				if len(parts) >= 2 {
					oidSuffix := parts[len(parts)-2] + "." + parts[len(parts)-1]
					data.Trays["input_"+oidSuffix] = result.Value
				}
			}
		}
	}

	// WALK exhaustivo de bandejas de salida
	baseOIDOutput := "1.3.6.1.2.1.43.9.2.1"
	results, err = client.Walk(baseOIDOutput, ctx)
	if err == nil {
		for _, result := range results {
			if result.Value != "" && result.Value != "0" {
				parts := strings.Split(result.OID, ".")
				if len(parts) >= 2 {
					oidSuffix := parts[len(parts)-2] + "." + parts[len(parts)-1]
					data.Trays["output_"+oidSuffix] = result.Value
				}
			}
		}
	}
}

// sanitizeNetworkValue limpia valores de red que puedan contener datos basura
func sanitizeNetworkValue(val interface{}) string {
	valStr := fmt.Sprintf("%v", val)

	// Limpiar null terminators
	valStr = strings.TrimRight(valStr, "\x00")

	// Si aún contiene caracteres de reemplazo, es datos inválido - retornar vacío
	if strings.Contains(valStr, "\ufffd") {
		return ""
	}

	return valStr
}

// collectNetworkInfo obtiene información de red detallada
func (dc *DataCollector) collectNetworkInfo(client *snmp.SNMPClient, data *PrinterData) {
	ctx := snmp.NewContext()

	// OIDs de red comunes
	networkOIDs := map[string]string{
		oids.IPAddress:   "ipAddress",
		oids.MacAddress:  "macAddress",
		oids.Gateway:     "gateway",
		oids.SubnetMask:  "subnetMask",
		oids.DhcpEnabled: "dhcpEnabled",
	}

	oidList := make([]string, 0, len(networkOIDs))
	for oid := range networkOIDs {
		oidList = append(oidList, oid)
	}

	values, err := client.GetMultiple(oidList, ctx)
	if err != nil {
		return
	}

	for oid, fieldName := range networkOIDs {
		if val, exists := values[oid]; exists && val != nil && val != "" {
			data.NetworkInfo[fieldName] = sanitizeNetworkValue(val)
		}
	}
}

// collectAdminInfo obtiene información administrativa útil para toma de decisiones
func (dc *DataCollector) collectAdminInfo(client *snmp.SNMPClient, data *PrinterData) {
	ctx := snmp.NewContext()

	// OIDs administrativos útiles
	adminOIDs := map[string]string{
		oids.SystemDescription: "systemDescription",
		oids.SystemLocation:    "systemLocation",
		oids.SystemUptime:      "systemUptime",
		oids.SystemServices:    "systemServices",
	}

	oidList := make([]string, 0, len(adminOIDs))
	for oid := range adminOIDs {
		oidList = append(oidList, oid)
	}

	values, err := client.GetMultiple(oidList, ctx)
	if err != nil {
		return
	}

	for oid, fieldName := range adminOIDs {
		if val, exists := values[oid]; exists && val != nil && val != "" {
			valStr := sanitizeNetworkValue(val)

			// Procesar SystemUptime especialmente (convertir de ticks a formato legible)
			if fieldName == "systemUptime" {
				if uptimeStr, ok := val.(string); ok {
					data.AdminInfo[fieldName] = formatUptime(uptimeStr)
				}
			} else if fieldName == "systemDescription" {
				// Extraer información útil de la descripción
				data.AdminInfo[fieldName] = extractAdminInfo(valStr)
			} else {
				// Para systemLocation y otros campos, guardar directamente
				data.AdminInfo[fieldName] = valStr
			}
		}
	}
}

// formatUptime convierte ticks de SNMP (centésimas de segundo) a formato legible
func formatUptime(uptimeStr string) string {
	// uptimeStr puede ser como "217143009" (en centésimas de segundo)
	// Intentar parsear como número
	var ticks int64
	if _, err := fmt.Sscanf(uptimeStr, "%d", &ticks); err != nil {
		return uptimeStr
	}

	// Convertir a segundos
	seconds := ticks / 100
	if seconds < 0 {
		return uptimeStr
	}

	days := seconds / 86400
	seconds %= 86400
	hours := seconds / 3600
	seconds %= 3600
	minutes := seconds / 60
	seconds %= 60

	return fmt.Sprintf("%d días, %d horas, %d minutos, %d segundos", days, hours, minutes, seconds)
}

// extractAdminInfo extrae datos útiles de la descripción del sistema
func extractAdminInfo(description string) map[string]string {
	info := make(map[string]string)

	// Buscar patrones comunes:
	// "System Administrator name: X; ... location: Y; ... phone: Z"

	// Para ahora, retornar la descripción completa y dejar que el frontend la parsee
	// En futuro, se puede expandir para extraer componentes específicos
	info["description"] = description

	// Intentar extraer ubicación si está disponible
	if strings.Contains(description, "location") {
		parts := strings.Split(description, ";")
		for _, part := range parts {
			if strings.Contains(strings.ToLower(part), "location") {
				colonParts := strings.Split(part, ":")
				if len(colonParts) > 1 {
					info["location"] = strings.TrimSpace(colonParts[1])
					break
				}
			}
		}
	}

	return info
}

// extractLocationFromDiscovered extrae la ubicación de los datos descubiertos en Identification
func (dc *DataCollector) extractLocationFromDiscovered(data *PrinterData) {
	// El OID 1.3.6.1.2.1.1.6.0 se guarda como "generalInfo_1_3_6_1_2_1_1_6_0"
	locationKey := "generalInfo_1_3_6_1_2_1_1_6_0"

	if location, exists := data.Identification[locationKey]; exists && location != nil {
		locationStr := fmt.Sprintf("%v", location)
		if locationStr != "" && locationStr != "0" && !strings.Contains(locationStr, "\ufffd") {
			data.AdminInfo["systemLocation"] = sanitizeNetworkValue(locationStr)
		}
	}
}

// discoverAdditionalData realiza WALK exhaustivos para descobrir datos adicionales
func (dc *DataCollector) discoverAdditionalData(client *snmp.SNMPClient, data *PrinterData) {
	ctx := snmp.NewContext()

	// WALK en múltiples OID base para descubrir datos no identificados
	oidsToWalk := []struct {
		name   string
		basOID string
	}{
		// Estándares
		{"consumables", "1.3.6.1.2.1.43.11.1.1"},
		{"pageCounters", "1.3.6.1.2.1.43.10.2.1"},
		{"deviceInfo", "1.3.6.1.2.1.25.3.2.1"},
		{"environment", "1.3.6.1.2.1.25.3.3.1"},
		{"generalInfo", "1.3.6.1.2.1.1"},
		// Xerox
		{"xeroxCounters", "1.3.6.1.4.1.253.8.53.3.2.1"},
		{"xeroxSupplies", "1.3.6.1.4.1.253.8.53.13"},
		// HP
		{"hpCounters", "1.3.6.1.4.1.11.2.3.9.4.2.1.4"},
		{"hpSupplies", "1.3.6.1.4.1.11.2.3.9.4.3"},
		{"hpStatus", "1.3.6.1.4.1.11.2.3.9.4.2.1.5"},
		// Samsung
		{"samsungCounters", "1.3.6.1.4.1.236.11.5.1.1"},
		{"samsungSupplies", "1.3.6.1.4.1.236.11.5.11.1"},
		{"samsungStatus", "1.3.6.1.4.1.236.11.5.11.7"},
		// Kyocera
		{"kyoceraCounters", "1.3.6.1.4.1.2297.3"},
		// Ricoh
		{"ricohCounters", "1.3.6.1.4.1.367.3.2.1"},
	}

	// Map adicional para almacenar datos descubiertos
	additionalData := make(map[string]interface{})

	for _, oidGroup := range oidsToWalk {
		results, err := client.Walk(oidGroup.basOID, ctx)
		if err != nil {
			continue
		}

		for _, result := range results {
			if result.Value == "" || result.Value == "0" || strings.HasPrefix(result.Value, "-") {
				continue
			}

			// Crear clave descriptiva
			// Trim el punto inicial del OID si existe antes de reemplazar puntos con guiones
			oidTrimmed := strings.TrimPrefix(result.OID, ".")
			key := fmt.Sprintf("%s_%s", oidGroup.name, strings.ReplaceAll(oidTrimmed, ".", "_"))

			// Evitar duplicados en secciones ya pobladas
			_, inID := data.Identification[key]
			_, inStatus := data.Status[key]
			_, inCounters := data.Counters[key]
			_, inSupplies := data.Supplies[key]
			_, inTrays := data.Trays[key]
			_, inNetworkInfo := data.NetworkInfo[key]

			if !inID && !inStatus && !inCounters && !inSupplies && !inTrays && !inNetworkInfo {
				additionalData[key] = result.Value
			}
		}
	}

	// Agregar datos descubiertos en las secciones existentes
	if len(additionalData) > 0 {
		for key, val := range additionalData {
			if strings.Contains(key, "counter") || strings.Contains(key, "page") || strings.Contains(key, "count") {
				data.Counters[key] = val
			} else if strings.Contains(key, "status") || strings.Contains(key, "error") {
				data.Status[key] = val
			} else if strings.Contains(key, "supply") || strings.Contains(key, "consumable") || strings.Contains(key, "toner") || strings.Contains(key, "drum") {
				data.Supplies[key] = val
			} else if strings.Contains(key, "tray") || strings.Contains(key, "input") || strings.Contains(key, "output") {
				data.Trays[key] = val
			} else if strings.Contains(key, "network") || strings.Contains(key, "ip") || strings.Contains(key, "mac") {
				data.NetworkInfo[key] = val
			} else {
				data.Identification[key] = val
			}
		}
	}
}

// normalizeData procesa datos crudos para presentación legible
func (dc *DataCollector) normalizeData(data *PrinterData) {
	// Normalizar consumibles con porcentajes y descripciones
	data.NormalizedSupplies = dc.normalizeSupplies(data.Supplies)

	// Normalizar contadores
	data.NormalizedCounters = dc.normalizeCounters(data.Counters)
}

// normalizeSupplies convierte datos crudos de consumibles a formato legible
func (dc *DataCollector) normalizeSupplies(supplies map[string]interface{}) map[string]interface{} {
	normalized := make(map[string]interface{})

	// Mapeo de OIDs normalizados que ya existen
	for key, val := range supplies {
		if _, ok := val.(map[string]interface{}); ok {
			// Es un consumible ya estructurado (como tonerBlack, fusor)
			supplyMap := val.(map[string]interface{})
			name := key

			// Extraer valores
			var level, max float64
			if lvl, ok := supplyMap["level"].(string); ok {
				fmt.Sscanf(lvl, "%f", &level)
			}
			if mx, ok := supplyMap["max"].(string); ok {
				fmt.Sscanf(mx, "%f", &max)
			}

			// Calcular porcentaje
			var percentage float64
			if max > 0 {
				percentage = (level / max) * 100
			}

			desc := ""
			if d, ok := supplyMap["description"].(string); ok {
				desc = d
			}

			normalized[name] = map[string]interface{}{
				"description": desc,
				"level":       level,
				"max":         max,
				"percentage":  fmt.Sprintf("%.1f%%", percentage),
				"status":      getSupplyStatus(percentage),
			}
		}
	}

	// Procesar consumibles descubiertos por WALK sin normalizar
	var pendingConsumables map[string]map[string]string
	pendingConsumables = make(map[string]map[string]string)

	// Agrupar por índice
	for key, val := range supplies {
		if strings.Contains(key, "consumables_") {
			valStr := fmt.Sprintf("%v", val)
			parts := strings.Split(key, "_")
			if len(parts) >= 3 {
				index := parts[len(parts)-1]
				if pendingConsumables[index] == nil {
					pendingConsumables[index] = make(map[string]string)
				}

				// Clasificar por tipo de OID
				if strings.Contains(key, "1_1_1_6") { // Descripción
					pendingConsumables[index]["description"] = valStr
				} else if strings.Contains(key, "1_1_1_8") { // Máximo
					pendingConsumables[index]["max"] = valStr
				} else if strings.Contains(key, "1_1_1_9") { // Nivel
					pendingConsumables[index]["level"] = valStr
				}
			}
		}
	}

	// Crear entradas normalizadas para consumibles sin normalizar
	for idx, consumable := range pendingConsumables {
		if desc, ok := consumable["description"]; ok && desc != "" {
			var level, max float64
			fmt.Sscanf(consumable["level"], "%f", &level)
			fmt.Sscanf(consumable["max"], "%f", &max)

			var percentage float64
			if max > 0 && level >= 0 {
				percentage = (level / max) * 100
			}

			// Crear nombre amigable
			name := dc.normalizeConsumableName(desc)
			if name == "" {
				name = "consumable_" + idx
			}

			normalized[name] = map[string]interface{}{
				"description": desc,
				"level":       level,
				"max":         max,
				"percentage":  fmt.Sprintf("%.1f%%", percentage),
				"status":      getSupplyStatus(percentage),
			}
		}
	}

	return normalized
}

// normalizeConsumableName convierte descripción de consumible a nombre normalizado
func (dc *DataCollector) normalizeConsumableName(description string) string {
	desc := strings.ToLower(description)

	if strings.Contains(desc, "black toner") || strings.Contains(desc, "black cartridge") {
		return "tonerBlack"
	} else if strings.Contains(desc, "cyan") {
		return "tonerCyan"
	} else if strings.Contains(desc, "magenta") {
		return "tonerMagenta"
	} else if strings.Contains(desc, "yellow") {
		return "tonerYellow"
	} else if strings.Contains(desc, "fuser") {
		return "fusor"
	} else if strings.Contains(desc, "transfer roller") {
		return "transferRoller"
	} else if strings.Contains(desc, "waste") {
		return "wasteContainer"
	} else if strings.Contains(desc, "drum") {
		return "drum"
	} else if strings.Contains(desc, "belt") {
		return "belt"
	} else if strings.Contains(desc, "roller") {
		return "roller"
	}

	return ""
}

// getSupplyStatus retorna el estado legible de un consumible
func getSupplyStatus(percentage float64) string {
	if percentage >= 75 {
		return "OK"
	} else if percentage >= 50 {
		return "Bueno"
	} else if percentage >= 25 {
		return "Bajo"
	} else if percentage >= 10 {
		return "Crítico"
	} else {
		return "Agotado"
	}
}

// normalizeCounters convierte contadores a formato legible
func (dc *DataCollector) normalizeCounters(counters map[string]interface{}) map[string]interface{} {
	normalized := make(map[string]interface{})

	counterNames := map[string]string{
		"totalPages":       "Páginas Totales",
		"colorPages":       "Páginas a Color",
		"monochromedPages": "Páginas Monocromáticas",
		"printedPages":     "Páginas Impresas",
		"copiedPages":      "Páginas Copiadas",
		"scannedPages":     "Páginas Escaneadas",
		"faxedPages":       "Páginas Faxeadas",
	}

	// Mapeo de OIDs estándar RFC 3805 a nombres descriptivos
	// Uso del mapa centralizado desde pkg/oids
	rfc3805OIDMap := oids.MapaContadoresRFC3805

	for key, val := range counters {
		valStr := fmt.Sprintf("%v", val)

		// Evitar valores inválidos
		if strings.HasPrefix(valStr, "-") || valStr == "0" {
			continue
		}

		// Primero: buscar OID directo en tabla RFC centralizada
		if displayName, exists := rfc3805OIDMap[key]; exists {
			if count := parseCounter(valStr); count >= 0 {
				normalized[displayName] = count
			}
			continue
		}

		// Segundo: buscar por nombre conocido
		if displayName, ok := counterNames[key]; ok {
			if count := parseCounter(valStr); count >= 0 {
				normalized[displayName] = count
			}
		} else if strings.Contains(key, "pageCounters_") {
			// Procesar OIDs genéricos descubiertos
			oidPart := strings.TrimPrefix(key, "pageCounters__")

			// Intentar mapear OID genérico a tipo
			if strings.HasSuffix(oidPart, "_4_1_1") {
				// OID de totalPages estándar
				if count := parseCounter(valStr); count >= 0 {
					normalized["Páginas Totales"] = count
				}
			} else if strings.HasSuffix(oidPart, "_4_1_2") {
				// OID de monocromático
				if count := parseCounter(valStr); count >= 0 {
					normalized["Páginas Monocromáticas"] = count
				}
			} else if strings.HasSuffix(oidPart, "_4_1_3") {
				// OID de color pages
				if count := parseCounter(valStr); count >= 0 {
					normalized["Páginas a Color"] = count
				}
			} else if strings.HasSuffix(oidPart, "_2_1_1") {
				// Página - Impresora
				if count := parseCounter(valStr); count >= 0 {
					normalized["Página - Impresora"] = count
				}
			} else if strings.HasSuffix(oidPart, "_3_1_1") {
				// Página - Fotocopiadora
				if count := parseCounter(valStr); count >= 0 {
					normalized["Página - Fotocopiadora"] = count
				}
			} else if strings.HasSuffix(oidPart, "_5_1_1") {
				// Página - Escáner
				if count := parseCounter(valStr); count >= 0 {
					normalized["Página - Escáner"] = count
				}
			} else if strings.HasSuffix(oidPart, "_6_1_1") {
				// Página - Fax
				if count := parseCounter(valStr); count >= 0 {
					normalized["Página - Fax"] = count
				}
			}
		} else if strings.Contains(key, "vendor_") {
			// Procesar OIDs de fabricante
			if count := parseCounter(valStr); count >= 0 {
				// Crear nombre descriptivo del OID
				displayName := key
				if strings.Contains(key, "color") || strings.Contains(key, "Color") {
					displayName = "Páginas a Color"
				} else if strings.Contains(key, "mono") || strings.Contains(key, "Mono") || strings.Contains(key, "bw") {
					displayName = "Páginas Monocromáticas"
				}
				if _, exists := normalized[displayName]; !exists {
					normalized[displayName] = count
				}
			}
		}
	}

	return normalized
}

// parseCounter convierte valor a número, ignorando valores inválidos
func parseCounter(val string) int64 {
	val = strings.TrimSpace(val)
	var num int64
	if _, err := fmt.Sscanf(val, "%d", &num); err == nil {
		if num >= 0 {
			return num
		}
	}
	return -1
}
