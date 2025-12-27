package collector

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asaavedra/agent-snmp/pkg/profile"
	"github.com/asaavedra/agent-snmp/pkg/snmp"
)

// PrinterData contiene la información recolectada de una impresora
type PrinterData struct {
	IP                 string                 `json:"ip"`
	Brand              string                 `json:"brand"`
	Confidence         float64                `json:"confidence"`
	Identification     map[string]interface{} `json:"identification"`
	Status             map[string]interface{} `json:"status"`
	Supplies           map[string]interface{} `json:"supplies"`
	Counters           map[string]interface{} `json:"counters"`
	NetworkInfo        map[string]interface{} `json:"networkInfo,omitempty"`
	AdminInfo          map[string]interface{} `json:"adminInfo,omitempty"`
	NormalizedCounters map[string]interface{} `json:"normalizedCounters,omitempty"`
	NormalizedSupplies map[string]interface{} `json:"normalizedSupplies,omitempty"`
	Errors             []string               `json:"errors"`
	MissingSections    []string               `json:"missingSections"`
	Timestamp          time.Time              `json:"timestamp"`
	ResponseTime       time.Duration          `json:"responseTime"`
	ProbeAttempts      int                    `json:"probeAttempts"`
}

// CountersInfo agrupa contadores absolutos (para state/ y en queue/)
type CountersInfo struct {
	TotalPages int64 `json:"total_pages"`
	MonoPages  int64 `json:"mono_pages"`
	ColorPages int64 `json:"color_pages"`
	ScanPages  int64 `json:"scan_pages"`
	CopyPages  int64 `json:"copy_pages"`
	FaxPages   int64 `json:"fax_pages"`
}

// CountersDiff contiene solo cambios (deltas)
type CountersDiff struct {
	TotalPages int64 `json:"total_pages"`
	MonoPages  int64 `json:"mono_pages"`
	ColorPages int64 `json:"color_pages"`
	ScanPages  int64 `json:"scan_pages"`
	CopyPages  int64 `json:"copy_pages"`
	FaxPages   int64 `json:"fax_pages"`
}

// CountersSnapshot contiene contadores absolutos + deltas (para queue/)
type CountersSnapshot struct {
	Absolute      CountersInfo  `json:"absolute"`                 // Valores actuales
	Delta         *CountersDiff `json:"delta"`                    // Cambios desde última lectura (null si reset o sin estado)
	ResetDetected bool          `json:"reset_detected,omitempty"` // true si hubo reset
}

// PrinterState representa la última lectura conocida (almacenada en state/)
// Se usa para calcular deltas en el siguiente poll
type PrinterState struct {
	LastPollAt time.Time    `json:"last_poll_at"`
	Counters   CountersInfo `json:"counters"`
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
	config         Config
	rateLimiter    *RateLimiter
	profileManager *profile.Manager
}

// getPageCountFromStatus extrae page_count del mapa Status
func getPageCountFromStatus(status map[string]interface{}) int64 {
	if status == nil {
		return 0
	}

	if pageCount, exists := status["page_count"]; exists {
		return toInt64(pageCount)
	}

	return 0
}

// toInt64 convierte interface{} a int64
func toInt64(val interface{}) int64 {
	if val == nil {
		return 0
	}
	if v, ok := val.(int64); ok {
		return v
	}
	if v, ok := val.(float64); ok {
		return int64(v)
	}
	if v, ok := val.(int); ok {
		return int64(v)
	}
	if str, ok := val.(string); ok {
		if v, err := strconv.ParseInt(str, 10, 64); err == nil {
			return v
		}
	}
	return 0
}

// isSuspiciousValue detecta si un valor es sospechoso (overflow/garbage)
func isSuspiciousValue(val int64) bool {
	// Valores conocidos sospechosos
	suspiciousValues := map[int64]bool{
		2147483647: true, // INT32_MAX
		4294967295: true, // UINT32_MAX
		9223372036: true, // INT64_MAX/billion aproximadamente
		268435456:  true, // 2^28
		536870912:  true, // 2^29
		1073741824: true, // 2^30
		2097151:    true, // 2^21-1
		4194303:    true, // 2^22-1
		8388607:    true, // 2^23-1
		16777215:   true, // 2^24-1
		33554431:   true, // 2^25-1
		27327487:   true, // Observado en Samsung 192.168.150.35
		18935871:   true, // Observado en Samsung 192.168.150.35
		2002943:    true, // Observado en Samsung 192.168.150.35
	}

	if suspiciousValues[val] {
		return true
	}

	// Si es una potencia de 2, es sospechoso
	if val > 1000 && (val&(val-1)) == 0 {
		return true
	}

	return false
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

// NewDataCollector crea un nuevo colector
func NewDataCollector(config Config) *DataCollector {
	profileDir := "profiles"
	pm, err := profile.NewManager(profileDir)
	if err != nil {
		pm = nil
	}

	return &DataCollector{
		config:         config,
		rateLimiter:    NewRateLimiter(config.MaxConcurrentConnections),
		profileManager: pm,
	}
}

// CollectData recolecta datos de múltiples dispositivos en paralelo
func (dc *DataCollector) CollectData(ctx context.Context, devices []DeviceInfo) ([]PrinterData, error) {
	results := make([]PrinterData, 0, len(devices))
	resultsChan := make(chan PrinterData, len(devices))
	var wg sync.WaitGroup

	fmt.Printf("Iniciando recolección de %d dispositivos...\n", len(devices))
	startTime := time.Now()

	for _, device := range devices {
		wg.Add(1)

		go func(devInfo DeviceInfo) {
			defer wg.Done()

			dc.rateLimiter.Wait()
			defer dc.rateLimiter.Release()

			data := dc.collectFromDevice(ctx, devInfo)
			resultsChan <- data
		}(device)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for data := range resultsChan {
		results = append(results, data)
	}

	elapsed := time.Since(startTime)
	fmt.Printf("Recolección completada en %.2f segundos.\n", elapsed.Seconds())

	return results, nil
}

// collectFromDevice recolecta datos de un dispositivo específico
func (dc *DataCollector) collectFromDevice(_ context.Context, devInfo DeviceInfo) PrinterData {
	data := PrinterData{
		IP:                 devInfo.IP,
		Brand:              devInfo.Brand,
		Confidence:         devInfo.BrandConfidence,
		Identification:     make(map[string]interface{}),
		Status:             make(map[string]interface{}),
		Supplies:           make(map[string]interface{}),
		Counters:           make(map[string]interface{}),
		NetworkInfo:        make(map[string]interface{}),
		AdminInfo:          make(map[string]interface{}),
		NormalizedCounters: make(map[string]interface{}),
		NormalizedSupplies: make(map[string]interface{}),
		Errors:             []string{},
		MissingSections:    []string{},
		Timestamp:          time.Now(),
		ProbeAttempts:      1,
	}

	startTime := time.Now()

	// Crear cliente SNMP
	client := snmp.NewSNMPClient(devInfo.IP, dc.config.SNMPPort, devInfo.Community, "2c", dc.config.Timeout, dc.config.Retries)

	// Cargar perfil si está disponible, o ejecutar discovery
	var prof *profile.Profile
	var err error
	if dc.profileManager != nil {
		prof = dc.profileManager.GetOrDiscover(devInfo.IP)

		// Si no existe perfil, ejecutar discovery y guardar
		if prof == nil {
			fmt.Printf("[DISCOVERY] Ejecutando discovery para %s (%s)...\n", devInfo.IP, devInfo.Brand)
			prof, err = dc.profileManager.DiscoverAndSave(client, devInfo.IP, devInfo.Brand, "", "")
			if err != nil {
				data.Errors = append(data.Errors, fmt.Sprintf("Discovery failed: %v", err))
				fmt.Printf("[DISCOVERY] Error: %v\n", err)
			} else if prof != nil {
				fmt.Printf("[DISCOVERY] Perfil guardado para %s\n", devInfo.IP)
			}
		}
	}

	// PASO 1: Recolectar identificación
	dc.collectIdentification(&data, client)

	// PASO 2: Recolectar estado
	dc.collectStatus(&data, client)

	// PASO 3: Recolectar info de red
	dc.collectNetworkInfo(&data, client)

	// PASO 4: Recolectar consumibles dinámicamente
	walkCtx := snmp.NewContext()
	consumibles := dc.collectConsumiblesViaWalk(client, walkCtx, prof)
	for k, v := range consumibles {
		data.Supplies[k] = v
	}

	// PASO 5: Recolectar contadores
	dc.collectCounters(&data, client, prof)

	// PASO 6: Realizar WALK exhaustivo para descubrir datos adicionales
	dc.discoverAdditionalData(&data, client)

	// PASO 7: Extraer contadores que están disfrazados en supplies
	dc.extractPageCountersFromSupplies(&data)

	// PASO 8: Normalizar datos para presentación legible
	dc.normalizeData(&data)

	data.ResponseTime = time.Since(startTime)

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

// collectIdentification recolecta datos de identificación
func (dc *DataCollector) collectIdentification(data *PrinterData, client *snmp.SNMPClient) {
	oids := []string{
		"1.3.6.1.2.1.1.1.0",            // sysDescr
		"1.3.6.1.2.1.1.5.0",            // sysName (hostname)
		"1.3.6.1.2.1.1.2.0",            // sysObjectID
		"1.3.6.1.2.1.43.5.1.1.17.1",    // Modelo (RFC 3805)
		"1.3.6.1.2.1.43.5.1.1.5.1",     // Serial Number (RFC 3805: printerSerialNumber)
		"1.3.6.1.4.1.11.2.3.9.1.1.7.0", // HP Device Identification String
	}

	ctx := snmp.NewContext()
	results, err := client.GetMultiple(oids, ctx)
	if err != nil {
		data.Errors = append(data.Errors, fmt.Sprintf("Error en identificación: %v", err))
		return
	}

	// Mapeo de OID → campo canónico
	oidMapping := map[string]string{
		"1.3.6.1.2.1.1.1.0":         "sysDescr",
		"1.3.6.1.2.1.1.5.0":         "hostname", // sysName → hostname
		"1.3.6.1.2.1.1.2.0":         "sysObjectID",
		"1.3.6.1.2.1.43.5.1.1.17.1": "model",
		"1.3.6.1.2.1.43.5.1.1.5.1":  "serial_number",
	}

	for oid, val := range results {
		if val == nil {
			continue
		}

		valStr := strings.TrimSpace(fmt.Sprintf("%v", val))
		if valStr == "" || valStr == "0" {
			continue
		}

		// HP Device Identification String: parse HP-specific format
		if oid == "1.3.6.1.4.1.11.2.3.9.1.1.7.0" {
			dc.parseHPIdentificationString(valStr, data)
			continue
		}

		// Usar el mapeo para claves canónicas
		if fieldName, ok := oidMapping[oid]; ok {
			data.Identification[fieldName] = valStr
		}
	}

	if len(data.Identification) == 0 {
		data.MissingSections = append(data.MissingSections, "identification")
	}
}

// parseHPIdentificationString extrae información del string de identificación HP
// Formato: "MFG:HP;MDL:HP Officejet Pro X476dw MFP;CMD:...;DES:CN461A;...;SN:CN36FDJ03K;..."
func (dc *DataCollector) parseHPIdentificationString(idString string, data *PrinterData) {
	// Dividir por punto y coma
	pairs := strings.Split(idString, ";")

	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if value == "" {
			continue
		}

		switch key {
		case "MDL":
			// MDL = Model
			data.Identification["model"] = value
		case "SN":
			// SN = Serial Number
			data.Identification["serial_number"] = value
		case "DES":
			// DES = Designation code (alternative model identifier)
			if _, exists := data.Identification["model"]; !exists {
				data.Identification["designation"] = value
			}
		case "MFG":
			// MFG = Manufacturer
			data.Identification["manufacturer"] = value
		}
	}
}

// collectStatus recolecta estado de la impresora
func (dc *DataCollector) collectStatus(data *PrinterData, client *snmp.SNMPClient) {
	oids := []string{
		"1.3.6.1.2.1.25.3.2.1.5.1",    // device status (1=up, 2=down, etc)
		"1.3.6.1.2.1.43.13.4.1.7.1.1", // printer status (HR-MIB)
		"1.3.6.1.2.1.43.8.2.1.13.1.1", // error status
		"1.3.6.1.2.1.1.3.0",           // sysUpTime (centisegundos desde reinicio)
	}

	ctx := snmp.NewContext()
	results, err := client.GetMultiple(oids, ctx)
	if err != nil {
		// No es crítico si status falla, el printer puede trabajar sin esto
		return
	}

	// Procesar resultados
	for oid, val := range results {
		if val == nil {
			continue
		}

		valStr := strings.TrimSpace(fmt.Sprintf("%v", val))
		if valStr == "" || valStr == "0" {
			continue
		}

		switch oid {
		case "1.3.6.1.2.1.25.3.2.1.5.1":
			// Device status: 1=up, 2=down, 3=testing
			// Mapear a estado legible
			switch valStr {
			case "1":
				data.Status["state"] = "idle"
			case "2":
				data.Status["state"] = "offline"
			case "3":
				data.Status["state"] = "testing"
			default:
				data.Status["state"] = "unknown"
			}
			data.Status["device_status"] = valStr

		case "1.3.6.1.2.1.43.13.4.1.7.1.1":
			// Printer status bit field (HR-MIB)
			data.Status["printer_status"] = valStr

		case "1.3.6.1.2.1.43.8.2.1.13.1.1":
			data.Status["error_status"] = valStr

		case "1.3.6.1.2.1.1.3.0":
			// sysUpTime en centisegundos
			if uptimeCentiseconds, err := strconv.ParseInt(valStr, 10, 64); err == nil {
				uptimeSeconds := uptimeCentiseconds / 100
				data.Status["system_uptime_seconds"] = int(uptimeSeconds)
				data.Status["system_uptime"] = dc.formatUptime(uptimeSeconds)
			}
		}
	}

	// Si no hay state aún, establecer como desconocido
	if _, ok := data.Status["state"]; !ok {
		data.Status["state"] = "unknown"
	}
}

// formatUptime convierte segundos a formato legible "XXd HHh MMm"
func (dc *DataCollector) formatUptime(seconds int64) string {
	if seconds <= 0 {
		return ""
	}

	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	} else {
		return fmt.Sprintf("%dm", minutes)
	}
}

// collectNetworkInfo recolecta información de red
func (dc *DataCollector) collectNetworkInfo(data *PrinterData, client *snmp.SNMPClient) {
	oids := []string{
		"1.3.6.1.2.1.2.2.1.6.1",  // MAC address interface 1
		"1.3.6.1.2.1.2.2.1.6.2",  // MAC address interface 2 (useful for multi-interface devices)
		"1.3.6.1.2.1.4.20.1.1.1", // IP address
		"1.3.6.1.2.1.1.6.0",      // sysLocation
	}

	ctx := snmp.NewContext()
	results, err := client.GetMultiple(oids, ctx)
	if err != nil {
		data.Errors = append(data.Errors, fmt.Sprintf("Error en networkInfo: %v", err))
		return
	}

	for oid, val := range results {
		if val == nil {
			continue
		}

		valStr := fmt.Sprintf("%v", val)
		if valStr == "" {
			continue
		}

		switch oid {
		case "1.3.6.1.2.1.2.2.1.6.1", "1.3.6.1.2.1.2.2.1.6.2":
			// Take the first non-empty MAC address found
			if _, exists := data.NetworkInfo["macAddress"]; !exists && valStr != "" {
				data.NetworkInfo["macAddress"] = valStr
			}
		case "1.3.6.1.2.1.4.20.1.1.1":
			data.NetworkInfo["ipAddress"] = valStr
		case "1.3.6.1.2.1.1.6.0":
			data.NetworkInfo["location"] = valStr
		}
	}
}

// collectCounters recolecta contadores de páginas
func (dc *DataCollector) collectCounters(data *PrinterData, client *snmp.SNMPClient, prof *profile.Profile) {
	ctx := snmp.NewContext()

	// WALK del árbol completo de contadores RFC 3805: 1.3.6.1.2.1.43.10.2
	results, err := client.Walk("1.3.6.1.2.1.43.10.2", ctx)
	if err != nil || len(results) == 0 {
		results, _ = client.Walk("1.3.6.1.2.1.43.10", ctx)
	}

	// Recolectar TODOS los valores de contadores
	allCounters := make(map[string]int64)

	for _, result := range results {
		if result.Value == "" {
			continue
		}

		valStr := strings.TrimSpace(fmt.Sprintf("%v", result.Value))
		if valStr == "" {
			continue
		}

		if parsed, err := strconv.ParseInt(valStr, 10, 64); err == nil {
			// Filtrar valores de overflow (> 3 mil millones es casi seguro basura)
			if parsed > 0 && parsed <= 3_000_000_000 {
				normalizedOID := strings.TrimPrefix(result.OID, ".")
				allCounters[normalizedOID] = parsed
				data.Counters[normalizedOID] = parsed
			}
		}
	}

	// Usar el perfil si está disponible para mapeo más preciso
	if prof != nil && len(prof.OIDs["counters"]) > 0 {
		collectCountersFromProfile(data, client, prof)
	} else {
		// Fallback: mapeo basado en patrones y valores
		mapCountersFromWalk(data, allCounters)
	}

	// Asegurar que al menos intentamos vendor-specific
	if len(data.NormalizedCounters) == 0 || data.NormalizedCounters["total_pages"] == nil {
		collectCountersVendorSpecific(data, client)
	}

	// Fallback final: si total_pages no existe o es sospechoso, usar page_count
	pageCount := getPageCountFromStatus(data.Status)
	totalPages, hasTotal := data.NormalizedCounters["total_pages"]
	if !hasTotal || totalPages == nil || isSuspiciousValue(toInt64(totalPages)) {
		if pageCount > 0 {
			data.NormalizedCounters["total_pages"] = pageCount
			fmt.Printf("[DEBUG_COUNTER] Using page_count (%d) as total_pages (original was suspicious)\n", pageCount)
		}
	}

	if len(data.Counters) == 0 {
		data.MissingSections = append(data.MissingSections, "counters")
	}
}

// mapCountersFromWalk mapea contadores del WALK basándose en valores y patrones
func mapCountersFromWalk(data *PrinterData, allCounters map[string]int64) {
	// Estrategia: encontrar el valor más alto (probablemente total_pages)
	// y luego mapear el resto según lógica

	var maxVal int64 = 0
	var maxOID string
	var secondMaxVal int64 = 0
	var secondMaxOID string

	for oid, val := range allCounters {
		if val > maxVal {
			// Mover max actual a secondMax
			secondMaxVal = maxVal
			secondMaxOID = maxOID
			// Nuevo max
			maxVal = val
			maxOID = oid
		} else if val > secondMaxVal && val != maxVal {
			secondMaxVal = val
			secondMaxOID = oid
		}
	}

	// Mapeo simple: el valor más alto es total_pages
	if maxVal > 0 {
		data.NormalizedCounters["total_pages"] = maxVal
	}

	// El segundo valor más alto probablemente sea color_pages o mono_pages
	if secondMaxVal > 0 && secondMaxVal != maxVal {
		data.NormalizedCounters["color_pages"] = secondMaxVal
	}

	// Intentar encontrar otros contadores por patrón de OID o valor
	for oid, val := range allCounters {
		if val == maxVal || val == secondMaxVal {
			continue // Ya asignados
		}
		if val > 0 && val < 10000 { // Valores pequeños probablemente sean scan/copy/fax
			// Guardar como counter genérico
			counterKey := fmt.Sprintf("counter_%s", strings.ReplaceAll(oid, ".", "_"))
			data.NormalizedCounters[counterKey] = val
		}
	}
}

// collectCountersFromProfile extrae contadores usando el perfil descubierto
func collectCountersFromProfile(data *PrinterData, client *snmp.SNMPClient, prof *profile.Profile) {
	ctx := snmp.NewContext()

	vendorOIDs := prof.OIDs["counters"]
	if len(vendorOIDs) == 0 {
		return
	}

	// Para cada OID en el perfil, obtener su valor
	results, err := client.GetMultiple(vendorOIDs, ctx)
	if err != nil {
		return
	}

	// Recolectar todos los valores con sus índices
	type counterValue struct {
		idx   int
		oid   string
		value int64
	}

	var allValues []counterValue

	for i, oid := range vendorOIDs {
		val, exists := results[oid]
		if !exists || val == nil {
			continue
		}

		valStr := strings.TrimSpace(fmt.Sprintf("%v", val))
		if intVal, err := strconv.ParseInt(valStr, 10, 64); err == nil && intVal > 0 && intVal <= 3_000_000_000 {
			// IMPORTANTE: Filtrar valores sospechosos AQUÍ también
			if isSuspiciousValue(intVal) {
				continue
			}
			allValues = append(allValues, counterValue{idx: i, oid: oid, value: intVal})
		}
	}

	// Mapeo simple: por índice o por valor
	// Asumir que los primeros OIDs significativos corresponden a: total, mono, color, scan, copy, fax
	counterNames := []string{"total_pages", "mono_pages", "color_pages", "scan_pages", "copy_pages", "fax_pages"}

	// Si encontramos el patrón correcto: valor grande es total_pages
	// Reordenar para que el más grande sea primero
	for i := 0; i < len(allValues); i++ {
		for j := i + 1; j < len(allValues); j++ {
			if allValues[j].value > allValues[i].value {
				allValues[i], allValues[j] = allValues[j], allValues[i]
			}
		}
	}

	// Asignar en orden de valor descendente
	for i, cv := range allValues {
		if i >= len(counterNames) {
			break
		}
		data.NormalizedCounters[counterNames[i]] = cv.value
	}
}

// collectCountersVendorSpecific intenta extraer contadores de OIDs específicos por fabricante
func collectCountersVendorSpecific(data *PrinterData, client *snmp.SNMPClient) {
	ctx := snmp.NewContext()

	var vendorOIDs []string

	switch data.Brand {
	case "Samsung":
		// Samsung OIDs específicos
		vendorOIDs = []string{
			"1.3.6.1.4.1.236.11.5.1.1.1.1",  // total
			"1.3.6.1.4.1.236.11.5.1.1.1.4",  // mono
			"1.3.6.1.4.1.236.11.5.1.1.1.26", // color
			"1.3.6.1.4.1.236.11.5.1.1.1.30", // scan
		}
	case "HP":
		// HP OIDs específicos
		vendorOIDs = []string{
			"1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.1", // total
			"1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2", // mono
			"1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.3", // color
		}
	case "Xerox":
		// Xerox OIDs específicos
		vendorOIDs = []string{
			"1.3.6.1.4.1.253.8.53.3.2.1.1.1", // total pages
			"1.3.6.1.4.1.253.8.53.3.2.1.2.1", // mono pages
			"1.3.6.1.4.1.253.8.53.3.2.1.3.1", // color pages
			"1.3.6.1.4.1.253.8.53.3.2.1.4.1", // scan pages
			"1.3.6.1.4.1.253.8.53.3.2.1.5.1", // copy pages
			"1.3.6.1.4.1.253.8.53.3.2.1.6.1", // fax pages
		}
	}

	if len(vendorOIDs) == 0 {
		return
	}

	results, err := client.GetMultiple(vendorOIDs, ctx)
	if err != nil {
		return
	}

	counterNames := []string{"total_pages", "mono_pages", "color_pages", "scan_pages", "copy_pages", "fax_pages"}

	// Recolectar valores válidos con sus índices
	type counterValue struct {
		idx   int
		name  string
		value int64
		oid   string
	}

	var validValues []counterValue

	// Map OID responses to counter names in order
	for i, oid := range vendorOIDs {
		if i >= len(counterNames) {
			break
		}

		val, exists := results[oid]
		if !exists || val == nil {
			continue
		}

		valStr := strings.TrimSpace(fmt.Sprintf("%v", val))
		if valStr == "" || valStr == "0" {
			continue
		}

		if intVal, err := strconv.ParseInt(valStr, 10, 64); err == nil && intVal > 0 {
			// Filtrar overflow
			if intVal > 3_000_000_000 {
				continue
			}

			validValues = append(validValues, counterValue{idx: i, name: counterNames[i], value: intVal, oid: oid})
		}
	}

	// Ordenar por valor descendente para identificar correctamente
	for i := 0; i < len(validValues); i++ {
		for j := i + 1; j < len(validValues); j++ {
			if validValues[j].value > validValues[i].value {
				validValues[i], validValues[j] = validValues[j], validValues[i]
			}
		}
	}

	// Asignar: el mayor es total_pages, luego color_pages, etc.
	for i, cv := range validValues {
		if i == 0 {
			// El mayor debe ser total_pages
			data.NormalizedCounters["total_pages"] = cv.value
		} else if i == 1 {
			// Segundo mayor: probablemente color_pages
			data.NormalizedCounters["color_pages"] = cv.value
		} else {
			// El resto por nombre original pero validado
			data.NormalizedCounters[cv.name] = cv.value
		}
	}
}

// collectConsumiblesViaWalk descubre consumibles dinámicamente via WALK
// Si hay un profile, usa los OIDs descubiertos para extraer datos completos
func (dc *DataCollector) collectConsumiblesViaWalk(client *snmp.SNMPClient, ctx *snmp.Context, prof *profile.Profile) map[string]interface{} {
	consumibles := make(map[string]interface{})

	// Si tenemos un perfil con OIDs de supplies, usar esos directamente para obtener datos completos
	if prof != nil && len(prof.OIDs["supplies"]) > 0 {
		return dc.collectSuppliesFromProfile(client, ctx, prof)
	}

	// Fallback: WALK en múltiples OIDs estándar
	// IMPORTANTES: RFC 3805 vs. Vendor-specific
	oidsToTry := []string{
		"1.3.6.1.2.1.43.11.1.1.6",      // RFC 3805: Description
		"1.3.6.1.4.1.11.2.3.9.4.2.1.6", // HP proprietary supplies
	}

	var resultsDesc []snmp.WalkResult
	var err error

	// Intentar WALK en cada OID hasta obtener resultados
	for _, oid := range oidsToTry {
		resultsDesc, err = client.Walk(oid, ctx)
		if err == nil && len(resultsDesc) > 0 {
			break // Encontramos resultados, usar estos
		}
	}

	// Si no encontramos descripciones, retornar vacío
	if len(resultsDesc) == 0 {
		return consumibles
	}

	// WALK 2: Obtener niveles actuales (RFC 3805: 1.3.6.1.2.1.43.11.1.1.9)
	resultsLevel, err := client.Walk("1.3.6.1.2.1.43.11.1.1.9", ctx)
	if err != nil {
		resultsLevel = []snmp.WalkResult{}
	}

	// WALK 3: Obtener máximos (RFC 3805: 1.3.6.1.2.1.43.11.1.1.8)
	resultsMax, err := client.Walk("1.3.6.1.2.1.43.11.1.1.8", ctx)
	if err != nil {
		resultsMax = []snmp.WalkResult{}
	}

	// Mapeo de descripciones a claves normalizadas
	consumibleMapping := map[string]string{
		"black toner":     "tonerBlack",
		"black ink":       "tonerBlack", // HP usa "ink" en lugar de "toner"
		"cyan toner":      "tonerCyan",
		"cyan ink":        "tonerCyan", // HP usa "ink"
		"magenta toner":   "tonerMagenta",
		"magenta ink":     "tonerMagenta", // HP usa "ink"
		"yellow toner":    "tonerYellow",
		"yellow ink":      "tonerYellow", // HP usa "ink"
		"black drum":      "drumBlack",
		"cyan drum":       "drumCyan",
		"magenta drum":    "drumMagenta",
		"yellow drum":     "drumYellow",
		"fuser":           "fusor",
		"transfer roller": "transferRoller",
		"waste":           "cajaResiduos",
		"drum":            "drum",
	}

	// Construir maps de niveles y máximos (normalizar OIDs sin punto inicial)
	levelMap := make(map[string]string)
	maxMap := make(map[string]string)

	for _, result := range resultsLevel {
		normalizedOID := strings.TrimPrefix(result.OID, ".")
		levelMap[normalizedOID] = result.Value
	}
	for _, result := range resultsMax {
		normalizedOID := strings.TrimPrefix(result.OID, ".")
		maxMap[normalizedOID] = result.Value
	}

	// Procesar descripciones
	for _, result := range resultsDesc {
		if result.Value == "" {
			continue
		}

		// Normalizar OID (remover punto inicial)
		normalizedOID := strings.TrimPrefix(result.OID, ".")

		// Extraer índice del OID
		parts := strings.Split(normalizedOID, ".")
		if len(parts) == 0 {
			continue
		}
		index := parts[len(parts)-1]

		// Normalizar descripción
		normalizedKey := ""
		descLower := strings.ToLower(result.Value)
		for desc, key := range consumibleMapping {
			if strings.Contains(descLower, strings.ToLower(desc)) {
				normalizedKey = key
				break
			}
		}

		if normalizedKey != "" {
			// Construir OIDs de nivel y máximo
			levelOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.9.1.%s", index)
			maxOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.8.1.%s", index)

			// Obtener valores
			levelVal := levelMap[levelOID]
			maxVal := maxMap[maxOID]

			consumibles[normalizedKey] = map[string]interface{}{
				"description": result.Value,
				"level":       levelVal,
				"max":         maxVal,
			}
		}
	}

	return consumibles
}

// collectSuppliesFromProfile extrae información COMPLETA de supplies usando OIDs del perfil
// IMPORTANTE: Se queda con las implementaciones simples de WALK RFC3805
func (dc *DataCollector) collectSuppliesFromProfile(client *snmp.SNMPClient, ctx *snmp.Context, _ *profile.Profile) map[string]interface{} {
	// Para ahora, usar el WALK estándar - es más confiable
	// Las OIDs del perfil tienen estructura muy compleja y varían por marca

	consumibles := make(map[string]interface{})

	// WALK 1: Obtener descripciones de consumibles (RFC 3805: 1.3.6.1.2.1.43.11.1.1.6)
	resultsDesc, err := client.Walk("1.3.6.1.2.1.43.11.1.1.6", ctx)
	if err != nil {
		return consumibles
	}

	// WALK 2: Obtener niveles actuales (RFC 3805: 1.3.6.1.2.1.43.11.1.1.9)
	resultsLevel, err := client.Walk("1.3.6.1.2.1.43.11.1.1.9", ctx)
	if err != nil {
		resultsLevel = []snmp.WalkResult{}
	}

	// WALK 3: Obtener máximos (RFC 3805: 1.3.6.1.2.1.43.11.1.1.8)
	resultsMax, err := client.Walk("1.3.6.1.2.1.43.11.1.1.8", ctx)
	if err != nil {
		resultsMax = []snmp.WalkResult{}
	}

	// WALK 4: Obtener tipos (RFC 3805: 1.3.6.1.2.1.43.11.1.1.2)
	resultsType, err := client.Walk("1.3.6.1.2.1.43.11.1.1.2", ctx)
	if err != nil {
		resultsType = []snmp.WalkResult{}
	}

	// WALK 5: Obtener modelos/números de pieza (RFC 3805: 1.3.6.1.2.1.43.11.1.1.4)
	resultsModel, err := client.Walk("1.3.6.1.2.1.43.11.1.1.4", ctx)
	if err != nil {
		resultsModel = []snmp.WalkResult{}
	}

	// WALK 6: Obtener estados (RFC 3805: 1.3.6.1.2.1.43.11.1.1.7)
	resultsState, err := client.Walk("1.3.6.1.2.1.43.11.1.1.7", ctx)
	if err != nil {
		resultsState = []snmp.WalkResult{}
	}

	// Mapeo de descripciones a claves normalizadas
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
		"waste":           "cajaResiduos",
		"drum":            "drum",
	}

	// Construir maps de niveles, máximos, tipos, modelos, estados
	levelMap := make(map[string]string)
	maxMap := make(map[string]string)
	typeMap := make(map[string]string)
	modelMap := make(map[string]string)
	stateMap := make(map[string]string)

	for _, result := range resultsLevel {
		normalizedOID := strings.TrimPrefix(result.OID, ".")
		levelMap[normalizedOID] = result.Value
	}
	for _, result := range resultsMax {
		normalizedOID := strings.TrimPrefix(result.OID, ".")
		maxMap[normalizedOID] = result.Value
	}
	for _, result := range resultsType {
		normalizedOID := strings.TrimPrefix(result.OID, ".")
		typeMap[normalizedOID] = result.Value
	}
	for _, result := range resultsModel {
		normalizedOID := strings.TrimPrefix(result.OID, ".")
		modelMap[normalizedOID] = result.Value
	}
	for _, result := range resultsState {
		normalizedOID := strings.TrimPrefix(result.OID, ".")
		stateMap[normalizedOID] = result.Value
	}

	// Procesar descripciones
	for _, result := range resultsDesc {
		if result.Value == "" {
			continue
		}

		// Normalizar OID (remover punto inicial)
		normalizedOID := strings.TrimPrefix(result.OID, ".")

		// Extraer índice del OID (el último número)
		parts := strings.Split(normalizedOID, ".")
		if len(parts) == 0 {
			continue
		}
		index := parts[len(parts)-1]

		// Normalizar descripción
		normalizedKey := ""
		descLower := strings.ToLower(result.Value)
		for desc, key := range consumibleMapping {
			if strings.Contains(descLower, strings.ToLower(desc)) {
				normalizedKey = key
				break
			}
		}

		// Si no matchea con mapping conocido, usar la descripción como está
		if normalizedKey == "" {
			normalizedKey = strings.ToLower(strings.ReplaceAll(result.Value, " ", "_"))
		}

		if normalizedKey != "" {
			// Construir OIDs de nivel, máximo, tipo, modelo, estado
			levelOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.9.1.%s", index)
			maxOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.8.1.%s", index)
			typeOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.2.1.%s", index)
			modelOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.4.1.%s", index)
			stateOID := fmt.Sprintf("1.3.6.1.2.1.43.11.1.1.7.1.%s", index)

			// Obtener valores
			levelVal := levelMap[levelOID]
			maxVal := maxMap[maxOID]
			typeVal := typeMap[typeOID]
			modelVal := modelMap[modelOID]
			stateVal := stateMap[stateOID]

			supplyInfo := map[string]interface{}{
				"description": result.Value,
			}

			if levelVal != "" {
				supplyInfo["level"] = levelVal
			}
			if maxVal != "" {
				supplyInfo["max"] = maxVal
			}
			if typeVal != "" {
				supplyInfo["type_code"] = typeVal // Type code del SNMP
				supplyInfo["component_type"] = dc.mapSupplyTypeToComponentType(typeVal)
			}
			if modelVal != "" && modelVal != "unknown" {
				supplyInfo["model"] = modelVal
				supplyInfo["part_number"] = modelVal
			}
			if stateVal != "" && stateVal != "0" {
				supplyInfo["state_code"] = stateVal
			}

			// Extraer brand/OEM de la descripción o modelo
			brand := dc.extractBrandFromSupply(result.Value, modelVal)
			if brand != "" {
				supplyInfo["brand"] = brand
			}

			consumibles[normalizedKey] = supplyInfo
		}
	}

	return consumibles
}

// mapSupplyTypeToComponentType mapea códigos SNMP de tipo a nombres legibles
func (dc *DataCollector) mapSupplyTypeToComponentType(typeCode string) string {
	// Mapeo de RFC 3805 supply types
	typeMap := map[string]string{
		"1":  "other",
		"2":  "unknown",
		"3":  "toner_cartridge",
		"4":  "waste_toner",
		"5":  "ink_cartridge",
		"6":  "ink_ribbon",
		"7":  "paper_tray",
		"8":  "staples",
		"9":  "cover",
		"10": "band",
		"11": "developer",
		"12": "fuser",
		"13": "transfer_unit",
		"14": "toner_cartridge_waste",
		"15": "photoconductor_unit",
		"16": "imaging_unit",
		"17": "transfer_roller",
		"18": "separation_pad",
		"19": "feed_roller",
		"20": "pickup_roller",
		"21": "separation_roller",
		"22": "duplexer",
		"23": "paper_exit",
		"24": "paper_entrance",
	}

	if val, exists := typeMap[typeCode]; exists {
		return val
	}
	return ""
}

// extractBrandFromSupply intenta detectar la marca/fabricante del consumible
func (dc *DataCollector) extractBrandFromSupply(description, model string) string {
	brands := []string{"Samsung", "Canon", "Fujifilm", "Xerox", "HP", "Ricoh", "Konica Minolta", "Sharp", "OKI", "Lexmark"}

	desc_lower := strings.ToLower(description)
	model_lower := strings.ToLower(model)

	for _, brand := range brands {
		brand_lower := strings.ToLower(brand)
		if strings.Contains(desc_lower, brand_lower) || strings.Contains(model_lower, brand_lower) {
			return brand
		}
	}

	// Intentar deducir de números de parte comunes
	if strings.Contains(model_lower, "crum") || strings.Contains(model_lower, "cltp") {
		return "Samsung"
	}
	if strings.Contains(model_lower, "006r") || strings.Contains(model_lower, "001r") {
		return "Xerox"
	}
	if strings.Contains(model_lower, "ce") || strings.Contains(model_lower, "cf") {
		return "HP"
	}

	return ""
}

// discoverAdditionalData realiza WALK exhaustivo para descubrir datos adicionales
func (dc *DataCollector) discoverAdditionalData(data *PrinterData, client *snmp.SNMPClient) {
	type OIDGroup struct {
		name   string
		basOID string
	}

	var oidsToWalk []OIDGroup
	oidsToWalk = append(oidsToWalk, OIDGroup{name: "counters", basOID: "1.3.6.1.2.1.43.10"})
	oidsToWalk = append(oidsToWalk, OIDGroup{name: "supplies", basOID: "1.3.6.1.2.1.43.11"})
	oidsToWalk = append(oidsToWalk, OIDGroup{name: "status", basOID: "1.3.6.1.2.1.43.13"})

	ctx := snmp.NewContext()

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
			oidTrimmed := strings.TrimPrefix(result.OID, ".")
			key := fmt.Sprintf("%s_%s", oidGroup.name, strings.ReplaceAll(oidTrimmed, ".", "_"))

			// Evitar duplicados
			_, inID := data.Identification[key]
			_, inStatus := data.Status[key]
			_, inCounters := data.Counters[key]
			_, inSupplies := data.Supplies[key]

			if !inID && !inStatus && !inCounters && !inSupplies {
				// Clasificar datos
				if strings.Contains(key, "counter") || strings.Contains(key, "page") {
					data.Counters[key] = result.Value
				} else if strings.Contains(key, "status") {
					data.Status[key] = result.Value
				} else if strings.Contains(key, "supply") || strings.Contains(key, "consumable") || strings.Contains(key, "toner") {
					data.Supplies[key] = result.Value
				} else {
					data.Identification[key] = result.Value
				}
			}
		}
	}
}

// extractPageCountersFromSupplies extrae contadores de página que están en supplies (Xerox, Samsung)
func (dc *DataCollector) extractPageCountersFromSupplies(data *PrinterData) {
	if data.Supplies == nil {
		return
	}

	// OIDs Xerox con contadores disfrazados de supplies
	xeroxPageCounterOIDs := map[string]string{
		"xeroxSupplies_1_3_6_1_4_1_253_8_53_13_2_1_2_1_20_29": "colorPages",
		"xeroxSupplies_1_3_6_1_4_1_253_8_53_13_2_1_2_1_20_7":  "monochromedPages",
		"xeroxSupplies_1_3_6_1_4_1_253_8_53_13_2_1_2_1_20_1":  "totalPages",
	}

	// Samsung page counter OIDs
	samsungPageCounterOIDs := map[string]string{
		"samsungSupplies_1_3_6_1_4_1_236_11_5_11_26_1_1_2_0": "totalPages",
		"samsungSupplies_1_3_6_1_4_1_236_11_5_11_26_1_1_3_0": "colorPages",
	}

	// Procesar Xerox
	for oid, counterName := range xeroxPageCounterOIDs {
		if val, exists := data.Supplies[oid]; exists {
			valStr := fmt.Sprintf("%v", val)
			if !strings.HasPrefix(valStr, "-") && valStr != "0" {
				data.Counters[counterName] = valStr
			}
		}
	}

	// Procesar Samsung
	for oid, counterName := range samsungPageCounterOIDs {
		if val, exists := data.Supplies[oid]; exists {
			valStr := fmt.Sprintf("%v", val)
			if !strings.HasPrefix(valStr, "-") && valStr != "0" {
				data.Counters[counterName] = valStr
			}
		}
	}
}

// normalizeData normaliza y procesa datos para presentación legible
func (dc *DataCollector) normalizeData(data *PrinterData) {
	data.NormalizedSupplies = dc.normalizeSupplies(data.Supplies)

	// IMPORTANTE: NormalizedCounters ya fue llenado en collectCounters()
	// solo rellenamos si está vacío (fallback)
	if len(data.NormalizedCounters) == 0 {
		data.NormalizedCounters = dc.normalizeCounters(data.Counters)
	}
}

// normalizeSupplies convierte datos crudos de consumibles a formato legible
func (dc *DataCollector) normalizeSupplies(supplies map[string]interface{}) map[string]interface{} {
	normalized := make(map[string]interface{})

	for key, val := range supplies {
		if supplyMap, ok := val.(map[string]interface{}); ok {
			// Es un consumible estructurado (tonerBlack, fusor, etc)
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

	return normalized
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

	for key, val := range counters {
		valStr := fmt.Sprintf("%v", val)

		// Evitar valores inválidos
		if strings.HasPrefix(valStr, "-") || valStr == "0" {
			continue
		}

		// Buscar por nombre conocido
		if displayName, ok := counterNames[key]; ok {
			if count := parseCounter(valStr); count >= 0 {
				normalized[displayName] = count
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
