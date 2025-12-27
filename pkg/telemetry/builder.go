package telemetry

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/asaavedra/agent-snmp/pkg/collector"
)

// Builder transforma PrinterData → Telemetry
// Responsabilidad ÚNICA: mapear campos sin lógica SNMP
// Si mañana cambias protocolo (SNMP → REST), Builder NO cambia
type Builder struct {
	source AgentSource // quién envía (agent_id, hostname, os, version)
}

// NewBuilder crea un nuevo builder
func NewBuilder(source AgentSource) *Builder {
	return &Builder{
		source: source,
	}
}

// sanitizeEmptyString convierte strings vacíos a nil (que será null en JSON)
// Se usa para campos opcionales que pueden no existir en algunos printers
// Retorna *string: si el string está vacío, retorna nil; sino retorna pointer al string
func (b *Builder) sanitizeEmptyString(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil // nil en JSON se serializa como null
	}
	return &s
}

// Build convierte un PrinterData a Telemetry (evento para queue/)
// Retorna un snapshot completo de la impresora con todas sus secciones
// Parámetro delta: se calcula desde state/ y se pasa aquí
func (b *Builder) Build(data *collector.PrinterData, delta *collector.CountersDiff, resetDetected bool) (*Telemetry, error) {
	if data == nil {
		return nil, fmt.Errorf("printer data cannot be nil")
	}

	// Construir identidad de la impresora
	// IMPORTANTE: TRIM todos los strings para evitar problemas en backend
	// Usar null en JSON para campos vacíos (no strings vacíos)
	printer := PrinterInfo{
		ID:              b.buildPrinterID(data),
		IP:              data.IP,
		Brand:           strings.TrimSpace(data.Brand),
		BrandConfidence: data.Confidence,
		Model:           b.sanitizeEmptyString(b.extractModel(data)),
		SerialNumber:    b.sanitizeEmptyString(b.extractSerialNumber(data)),
		Hostname:        b.sanitizeEmptyString(b.extractHostname(data)),
		MacAddress:      b.sanitizeEmptyString(b.extractMacAddress(data)),
	}

	// Construir counters (absolute + delta)
	counters := b.buildCounters(data, delta, resetDetected)

	// Construir supplies (nil si no hay)
	supplies := b.buildSupplies(data)

	// Construir alerts (nil si no hay)
	alerts := b.buildAlerts(data)

	// Construir metrics
	metrics := b.buildMetrics(data)

	// Generar event_id único
	eventID := b.buildEventID(printer, data.Timestamp)

	// Construir el Telemetry final (evento para queue/)
	// IMPORTANTE: SIEMPRE usar UTC para timestamps (backend maneja timezones)
	telemetry := &Telemetry{
		SchemaVersion: "1.0.0", // Congelado
		EventID:       eventID,
		CollectedAt:   data.Timestamp.UTC(),
		Source:        b.source,
		Printer:       printer,
		Counters:      counters,
		Supplies:      supplies, // nil si no aplica
		Alerts:        alerts,   // nil si no aplica
		Metrics:       metrics,
	}

	return telemetry, nil
}

// buildPrinterID genera un ID único, estable y corto
// Prioridad: MAC (más estable) → Serial (única) → IP (fallback)
// Resultado es lowercase sin caracteres especiales
func (b *Builder) buildPrinterID(data *collector.PrinterData) string {
	// 1. Intentar usar MAC address (la más estable)
	// Buscar en NetworkInfo
	if data.NetworkInfo != nil {
		if macAddress, ok := data.NetworkInfo["macAddress"].(string); ok && macAddress != "" {
			// Limpiar MAC: remover puntos y convertir a lowercase
			cleanMac := strings.ToLower(strings.ReplaceAll(macAddress, ":", ""))
			if len(cleanMac) >= 12 {
				return cleanMac
			}
		}
	}

	// 2. Fallback a serial number
	serial := strings.TrimSpace(b.extractSerialNumber(data))
	if serial != "" {
		return strings.ToLower(serial)
	}

	// 3. Fallback a IP
	return data.IP
}

// buildCounters extrae los contadores acumulativos
func (b *Builder) buildCounters(data *collector.PrinterData, delta *collector.CountersDiff, resetDetected bool) *collector.CountersSnapshot {
	// Prioritario: NormalizedCounters (extraídos y mapeados correctamente)
	countersToUse := data.NormalizedCounters
	if len(countersToUse) == 0 {
		countersToUse = data.Counters
	}

	if len(countersToUse) == 0 {
		return nil
	}

	absolute := collector.CountersInfo{
		TotalPages: int64(b.extractCounter(countersToUse, "total_pages")),
		MonoPages:  int64(b.extractCounter(countersToUse, "mono_pages")),
		ColorPages: int64(b.extractCounter(countersToUse, "color_pages")),
		ScanPages:  int64(b.extractCounter(countersToUse, "scan_pages")),
		CopyPages:  int64(b.extractCounter(countersToUse, "copy_pages")),
		FaxPages:   int64(b.extractCounter(countersToUse, "fax_pages")),
	}

	snapshot := &collector.CountersSnapshot{
		Absolute:      absolute,
		Delta:         delta,
		ResetDetected: resetDetected,
	}

	return snapshot
}

// buildEventID genera un ID único para el evento
// Formato: {agent_id}::{printer_mac_or_ip}::{timestamp_unix}
func (b *Builder) buildEventID(printer PrinterInfo, timestamp time.Time) string {
	var printerKey string

	// Usar MAC si está disponible, sino usar IP
	if printer.MacAddress != nil && *printer.MacAddress != "" {
		printerKey = *printer.MacAddress
	} else {
		printerKey = printer.IP
	}

	// Remover caracteres especiales de MAC address
	key := strings.ReplaceAll(printerKey, ":", "")

	return fmt.Sprintf("%s::%s::%d", b.source.AgentID, key, timestamp.Unix())
}

// buildSupplies convierte supplies a SupplyInfo array
// Retorna nil si no hay supplies con datos útiles
// Filtra: vacíos, "unknown", level=0 sin maxLevel, solo nombres sin info
func (b *Builder) buildSupplies(data *collector.PrinterData) []SupplyInfo {
	if len(data.Supplies) == 0 {
		return nil // nil, no []SupplyInfo{} - más semántico
	}

	supplies := make([]SupplyInfo, 0)

	for _, supply := range data.Supplies {
		// Extraer campos crudos
		name := b.extractFieldAsString(supply, "name", "description")
		level := int64(b.extractFieldAsInt(supply, "level", "current"))
		maxLevel := int64(b.extractFieldAsInt(supply, "maxLevel", "max"))
		percentage := b.extractFieldAsInt(supply, "percentage", "percent")

		// FILTROS ESTRICTOS:
		// 1. Nombre vacío o "unknown"
		if name == "" || name == "unknown" {
			continue
		}

		// 2. Solo espacios
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		// 3. Si level=0 Y maxLevel=0 Y percentage=0 → datos inútiles
		// (excepto si hay name con info real)
		if level == 0 && maxLevel == 0 && percentage == 0 {
			// Si el nombre tiene info de S/N o descripción técnica, incluir
			// sino descartar
			lowerName := strings.ToLower(name)
			hasInfo := strings.Contains(lowerName, "s/n:") ||
				strings.Contains(lowerName, "serial") ||
				strings.Contains(lowerName, "part") ||
				strings.Contains(lowerName, "model") ||
				strings.Contains(lowerName, "firmware") ||
				strings.Contains(lowerName, "version") ||
				(len(name) > 50) // Si es muy largo, probablemente sea S/N

			if !hasInfo {
				continue // Skip si no hay dato útil
			}
		}

		// 4. Limpiar nombre: remover espacios extras y S/N de más
		cleanName := b.cleanSupplyName(name)
		if cleanName == "" {
			continue
		}

		// 5. CALCULAR porcentaje si no viene en los datos o es 0
		// Prioridad: campo "percentage" → calcular desde level/maxLevel
		calculatedPercentage := percentage
		if calculatedPercentage == 0 && maxLevel > 0 && level > 0 {
			calculatedPercentage = int((level * 100) / maxLevel)
		}

		// 6. Extraer campos adicionales para detalles completos
		model := b.extractFieldAsString(supply, "model", "partnumber", "part_number")
		serialNumber := b.extractFieldAsString(supply, "serial_number", "serial", "sn")
		description := b.extractFieldAsString(supply, "description", "desc")
		componentType := b.extractFieldAsString(supply, "component_type", "type_code")
		oem := b.extractFieldAsString(supply, "oem", "brand", "manufacturer")

		// Intentar extraer capacidad en páginas si está disponible
		pageCapacity := int64(b.extractFieldAsInt(supply, "page_capacity", "pages", "capacity"))

		// Si no tenemos serialNumber, intentar extraer de la descripción
		if serialNumber == "" && description != "" {
			serialNumber = b.extractSerialFromDescription(description)
		}

		// Si no tenemos model/part_number, intentar extraer de la descripción
		if model == "" && description != "" {
			model = b.extractPartNumberFromDescription(description)
		}

		si := SupplyInfo{
			ID:         b.normalizeToID(cleanName),
			Name:       cleanName,
			Type:       b.deduceSupplyType(cleanName),
			Level:      level,
			MaxLevel:   maxLevel,
			Percentage: calculatedPercentage,
			Status:     b.deduceSupplyStatus(calculatedPercentage),
			// Campos adicionales de detalles
			Model:         model,
			SerialNumber:  serialNumber,
			Description:   description,
			ComponentType: componentType,
			Brand:         oem,
			PageCapacity:  pageCapacity,
		}

		supplies = append(supplies, si)
	}

	if len(supplies) == 0 {
		return nil
	}

	return supplies
}

// buildAlerts extrae alertas activas del estado de consumibles
// Retorna nil si no hay alertas
func (b *Builder) buildAlerts(data *collector.PrinterData) []AlertInfo {
	if len(data.Supplies) == 0 {
		return nil
	}

	alerts := make([]AlertInfo, 0)

	// Generar alertas basadas en estado de supplies
	for _, supply := range data.Supplies {
		status := b.extractSupplyStatus(supply)

		// Solo crear alerta si el status es warning/critical
		if status == "critical" || status == "low" {
			severity := "warning"
			if status == "critical" {
				severity = "critical"
			}

			// Construir mensaje con modelo del supply si disponible
			supplyName := b.extractFieldAsString(supply, "name", "description")
			supplyModel := b.extractFieldAsString(supply, "model", "")
			percentage := b.extractFieldAsInt(supply, "percentage", "percent")

			message := fmt.Sprintf("%s is %s (%d%%)", supplyName, status, percentage)
			if supplyModel != "" {
				message = fmt.Sprintf("%s %s is %s (%d%%)", supplyName, supplyModel, status, percentage)
			}

			// Generar alert ID simple: {supply_type}_{status}
			// Usar cleanSupplyName y deduceSupplyType para obtener el tipo consistentemente
			cleanName := b.cleanSupplyName(supplyName)
			supplyType := b.deduceSupplyType(cleanName)
			if supplyType == "" {
				supplyType = "supply"
			}

			alert := AlertInfo{
				ID:         fmt.Sprintf("%s_%s", supplyType, status),
				Type:       "supply",
				Severity:   severity,
				Message:    message,
				DetectedAt: data.Timestamp,
			}
			alerts = append(alerts, alert)
		}
	}

	if len(alerts) == 0 {
		return nil
	}

	return alerts
}

// buildMetrics construye las métricas del poll
func (b *Builder) buildMetrics(data *collector.PrinterData) *MetricsInfo {
	// IMPORTANTE: SIEMPRE UTC en timestamps
	// RetryCount: número de reintentos (debe ser >= 0)
	retryCount := data.ProbeAttempts - 1
	if retryCount < 0 {
		retryCount = 0
	}

	metrics := &MetricsInfo{
		Polling: &PollingMetrics{
			ResponseTimeMs: int(data.ResponseTime.Milliseconds()),
			PollDurationMs: int(data.ResponseTime.Milliseconds()),
			OidSuccessRate: 0.95,
			RetryCount:     retryCount,
			LastPollAt:     data.Timestamp.UTC(),
			NextPollAt:     data.Timestamp.UTC().Add(1 * time.Hour),
			ErrorCount:     len(data.Errors),
		},
	}

	return metrics
}

// ============= HELPERS DE EXTRACCIÓN =============

func (b *Builder) extractModel(data *collector.PrinterData) string {
	if data.Identification == nil {
		return ""
	}

	// Preferencia de claves para modelo
	for _, key := range []string{"model", "model_name", "modelName", "printerModel"} {
		if model, ok := data.Identification[key].(string); ok && model != "" {
			model = strings.TrimSpace(model)
			// Validar que no sea un serial/asset ID
			if len(model) > 0 && !b.looksLikeSerialNumber(model) {
				return model
			}
		}
	}

	// Fallback a description solo si contiene palabras de modelo reales
	if description, ok := data.Identification["description"].(string); ok && description != "" {
		description = strings.TrimSpace(description)
		lowerDesc := strings.ToLower(description)
		// Solo usar description si tiene palabras model-like
		commonModelWords := []string{"m332", "m402", "m382", "officejet", "laserjet", "colorprint", "mfp", "copier", "ricoh"}
		for _, word := range commonModelWords {
			if strings.Contains(lowerDesc, word) {
				return description
			}
		}
	}

	return ""
}

// looksLikeSerialNumber detecta si un string parece ser S/N vs modelo real
func (b *Builder) looksLikeSerialNumber(s string) bool {
	// Patrones típicos de serial:
	// - Alfanuméricos SIN espacios y MUY específicos (ej: Z78RBJACB00011H)
	// - Contienen mayúsculas seguidas de números
	// - Típicamente 12-20 caracteres alfanuméricos puros
	// - NO contienen palabras comunes de modelo

	lower := strings.ToLower(s)

	// Palabras que indican MODELO (no serial)
	modelKeywords := []string{"officejet", "laserjet", "colorprint", "mfp", "multifunction",
		"pro", "plus", "enterprise", "copier", "xerox", "samsung", "ricoh", "m332", "m402", "m382", "m306"}
	for _, word := range modelKeywords {
		if strings.Contains(lower, word) {
			return false // Es modelo
		}
	}

	// Si es corto (<12 chars) Y totalmente alfanumérico, probablemente es ID
	if len(s) < 12 {
		// Chequear si es alfanumérico puro
		allAlphaNum := true
		for _, r := range s {
			if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				allAlphaNum = false
				break
			}
		}
		if allAlphaNum {
			return true
		}
	}

	// Si tiene espacios, probablemente es modelo (ej: "Samsung M332x Series")
	if strings.Contains(s, " ") {
		return false
	}

	// Si es alfanumérico puro de 12+ chars (sin espacios, sin marcas modelo), es serial
	allAlphaNum := true
	hasDigit := false
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			allAlphaNum = false
			break
		}
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
	}

	if allAlphaNum && hasDigit && len(s) >= 12 {
		return true // Looks like serial number
	}

	return false
}

func (b *Builder) extractSerialNumber(data *collector.PrinterData) string {
	if data.Identification == nil {
		return ""
	}

	// Buscar con clave canónica primero
	if serial, ok := data.Identification["serial_number"].(string); ok && serial != "" {
		serial = strings.TrimSpace(serial)
		// Validar que no sea un nombre de marca
		if !b.isBrandName(serial) {
			return serial
		}
	}

	// Fallback a serialNumber (antiguo)
	if serial, ok := data.Identification["serialNumber"].(string); ok && serial != "" {
		serial = strings.TrimSpace(serial)
		if !b.isBrandName(serial) {
			return serial
		}
	}

	return ""
}

// isBrandName detecta si un string es nombre de marca (Samsung Electronics, Xerox Corporation, etc)
func (b *Builder) isBrandName(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	brandPatterns := []string{
		"samsung",
		"xerox",
		"hp",
		"hewlett",
		"canon",
		"ricoh",
		"konica",
		"minolta",
		"kyocera",
		"panasonic",
		"electronics",
		"corporation",
		"company",
		"inc.",
		"limited",
	}
	for _, pattern := range brandPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (b *Builder) extractHostname(data *collector.PrinterData) string {
	if data.Identification == nil {
		return ""
	}

	// Buscar con clave canónica primero
	if hostname, ok := data.Identification["hostname"].(string); ok && hostname != "" {
		return hostname
	}

	// Fallback a sysName (antiguo)
	if sysName, ok := data.Identification["sysName"].(string); ok && sysName != "" {
		return sysName
	}

	return ""
}

func (b *Builder) extractMacAddress(data *collector.PrinterData) string {
	if data.NetworkInfo == nil {
		return ""
	}

	if mac, ok := data.NetworkInfo["macAddress"].(string); ok {
		return mac
	}

	return ""
}

func (b *Builder) extractState(data *collector.PrinterData) string {
	if data.Status == nil {
		return "unknown"
	}

	// IMPORTANTE: Si tenemos contadores/supplies, la impresora está online
	// No puede estar offline si tiene datos actualizados
	hasData := false
	if len(data.NormalizedCounters) > 0 {
		hasData = true
	}
	if len(data.Supplies) > 0 {
		hasData = true
	}

	if state, ok := data.Status["state"].(string); ok && state != "" {
		// Si dice offline pero tiene datos, cambiar a unknown (timeout puede haber sido después de recopilar)
		if state == "offline" && hasData {
			return "unknown" // Conectividad inconsistente
		}
		return state
	}

	return "unknown"
}

func (b *Builder) extractUptimeString(data *collector.PrinterData) string {
	if data.AdminInfo == nil {
		return ""
	}

	if uptime, ok := data.AdminInfo["systemUptime"].(string); ok {
		return uptime
	}

	return ""
}

func (b *Builder) extractUptimeSeconds(data *collector.PrinterData) int64 {
	// Extraer de AdminInfo["systemUptime"] y convertir a segundos
	// Formato: puede ser número raw (centésimas de segundo SNMP) o string parseado
	if data.AdminInfo == nil {
		return 0
	}

	uptimeStr, ok := data.AdminInfo["systemUptime"].(string)
	if !ok || uptimeStr == "" {
		return 0
	}

	uptimeStr = strings.TrimSpace(uptimeStr)

	// CASO 1: Intentar parsearlo como número puro (centésimas de segundo SNMP)
	// Sistema SNMP retorna timeticks en centésimas de segundo
	if uptimeNum, err := strconv.ParseInt(uptimeStr, 10, 64); err == nil && uptimeNum > 0 {
		// Convertir centésimas de segundo a segundos
		return uptimeNum / 100
	}

	// CASO 2: Parsear formato legible: "467 días, 13 horas, 57 minutos, 8 segundos"
	// O variantes: "467d, 13h, 57m, 8s" o "467 days, 13 hours, 57 minutes, 8 seconds"
	var days, hours, minutes, seconds int64

	// Split por comas y procesar cada parte
	parts := strings.Split(uptimeStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Buscar patrón: número + unidad
		if strings.Contains(strings.ToLower(part), "día") || strings.Contains(strings.ToLower(part), "day") {
			fmt.Sscanf(part, "%d", &days)
		} else if strings.Contains(strings.ToLower(part), "hora") || strings.Contains(strings.ToLower(part), "hour") {
			fmt.Sscanf(part, "%d", &hours)
		} else if strings.Contains(strings.ToLower(part), "minuto") || strings.Contains(strings.ToLower(part), "minute") {
			fmt.Sscanf(part, "%d", &minutes)
		} else if strings.Contains(strings.ToLower(part), "segundo") || strings.Contains(strings.ToLower(part), "second") {
			fmt.Sscanf(part, "%d", &seconds)
		}
	}

	// Calcular total en segundos
	totalSeconds := days*86400 + hours*3600 + minutes*60 + seconds
	if totalSeconds > 0 {
		return totalSeconds
	}

	return 0
}

func (b *Builder) extractLocation(data *collector.PrinterData) string {
	if data.AdminInfo == nil {
		return ""
	}

	if loc, ok := data.AdminInfo["systemLocation"].(string); ok {
		return loc
	}

	return ""
}

func (b *Builder) extractCounter(counters map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if val, ok := counters[key]; ok {
			// Intentar conversiones en orden
			if intVal, ok := val.(int); ok {
				return intVal
			}
			if int64Val, ok := val.(int64); ok {
				return int(int64Val)
			}
			if floatVal, ok := val.(float64); ok {
				return int(floatVal)
			}
			// IMPORTANTE: Los valores pueden venir como strings desde el collector
			// fmt.Sprintf("%v", val) produce strings
			if strVal, ok := val.(string); ok {
				if intVal, err := strconv.Atoi(strings.TrimSpace(strVal)); err == nil {
					return intVal
				}
			}
		}
	}

	return 0
}

// cleanSupplyName limpia el nombre de un consumible
// Remueve espacios extras, S/N, y deja solo la descripción útil
func (b *Builder) cleanSupplyName(name string) string {
	// 1. Trim espacios
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	// 2. Si contiene "S/N:" o ";SN" separar descripción de número de serie
	// Ej: "Fuser S/N:                " → "Fuser"
	// Ej: "Black Toner, PN 006R01509;SN99172880E000044B" → "Black Toner"
	// Ej: "Black Toner Cartridge S/N:CRUM-14101514763" → "Black Toner Cartridge"

	// Buscar ";SN" (Xerox format: "Name, PN xxx;SNyyy")
	if idx := strings.Index(strings.ToUpper(name), ";SN"); idx != -1 {
		name = name[:idx]
		name = strings.TrimSpace(name)
	}

	// Buscar "S/N:" (ISO/estándar format)
	if idx := strings.Index(strings.ToUpper(name), "S/N:"); idx != -1 {
		name = name[:idx]
		name = strings.TrimSpace(name)
	}

	// 3. Si contiene "Serial", "Part Number", "PN " (con espacio), "PN:", "PN=", separar
	// IMPORTANTE: Buscar "PN " (con espacio) ANTES que "PN:" para Xerox format
	for _, sep := range []string{"Serial", "Part Number", "PN ", "PN:", "PN=", "P/N:", "P/N ", "Model:", "Version:"} {
		lowerName := strings.ToLower(name)
		lowerSep := strings.ToLower(sep)
		if idx := strings.Index(lowerName, lowerSep); idx != -1 {
			name = name[:idx]
			name = strings.TrimSpace(name)
			break
		}
	}

	// 4. Remover comas finales (si algún separador dejó comas al final)
	name = strings.TrimSuffix(strings.TrimSpace(name), ",")
	name = strings.TrimSpace(name)

	// 5. Remover espacios múltiples
	name = strings.Join(strings.Fields(name), " ")

	// 6. Si el resultado es muy corto o vacío, retornar empty
	if len(name) < 3 {
		return ""
	}

	return name
}
func (b *Builder) extractSupplyID(supply interface{}) string {
	// supply es un map[string]interface{}
	if supplyMap, ok := supply.(map[string]interface{}); ok {
		// Buscar campo "id" primero
		if id, ok := supplyMap["id"].(string); ok && id != "" && id != "unknown" && id != "supply_unknown" {
			return id
		}
		// Si no hay ID válido, generar desde el nombre
		if name, ok := supplyMap["name"].(string); ok && name != "" {
			// Generar ID a partir del nombre normalizando
			// Ej: "Black Toner Cartridge" → "black_toner_cartridge"
			normalized := b.normalizeToID(name)
			if normalized != "" {
				return normalized
			}
		}
		// Si tampoco hay nombre, intentar buscar en otros campos
		if desc, ok := supplyMap["description"].(string); ok && desc != "" {
			normalized := b.normalizeToID(desc)
			if normalized != "" {
				return normalized
			}
		}
	}

	return "supply_unknown"
}

func (b *Builder) extractSupplyStatus(supply interface{}) string {
	if supplyMap, ok := supply.(map[string]interface{}); ok {
		// Intentar obtener status directo
		if status, ok := supplyMap["status"].(string); ok && status != "" && status != "unknown" {
			return status
		}

		// Deducir status a partir del porcentaje
		percentage := b.extractFieldAsInt(supply, "percentage", "percent")

		if percentage == 0 {
			// Intentar calcular desde level y max
			level := b.extractFieldAsInt(supply, "level", "current")
			maxLevel := b.extractFieldAsInt(supply, "maxLevel", "max")
			if maxLevel > 0 && level > 0 {
				percentage = (level * 100) / maxLevel
			}
		}

		return b.deduceSupplyStatus(percentage)
	}

	return "unknown"
}

// deduceSupplyType deduce el tipo de suministro a partir del nombre
func (b *Builder) deduceSupplyType(name string) string {
	lowerName := strings.ToLower(name)

	// Mapa de keywords → tipos
	typeMap := map[string]string{
		"toner":         "toner",
		"drum":          "drum",
		"cilindro":      "drum",
		"fuser":         "fuser",
		"fusor":         "fuser",
		"roller":        "roller",
		"rodillo":       "roller",
		"cartridge":     "cartridge",
		"cartucho":      "cartridge",
		"waste":         "waste",
		"residuo":       "waste",
		"transfer":      "transfer",
		"transferencia": "transfer",
		"pickup":        "pickup",
		"retirada":      "pickup",
	}

	// Buscar el primer match
	for keyword, supplyType := range typeMap {
		if strings.Contains(lowerName, keyword) {
			return supplyType
		}
	}

	return "consumable"
}

// deduceSupplyStatus deduce el estado basado en el porcentaje
func (b *Builder) deduceSupplyStatus(percentage int) string {
	if percentage <= 10 {
		return "critical"
	} else if percentage <= 25 {
		return "low"
	} else if percentage <= 75 {
		return "ok"
	}
	return "good"
}

func (b *Builder) extractFieldAsString(supply interface{}, keys ...string) string {
	if supplyMap, ok := supply.(map[string]interface{}); ok {
		for _, key := range keys {
			if val, ok := supplyMap[key].(string); ok && val != "" {
				return val
			}
		}
	}

	return ""
}

func (b *Builder) extractFieldAsInt(supply interface{}, keys ...string) int {
	if supplyMap, ok := supply.(map[string]interface{}); ok {
		for _, key := range keys {
			if intVal, ok := supplyMap[key].(int); ok {
				return intVal
			}
			if int64Val, ok := supplyMap[key].(int64); ok {
				return int(int64Val)
			}
			if floatVal, ok := supplyMap[key].(float64); ok {
				return int(floatVal)
			}
			// IMPORTANTE: Los supplies del collector vienen como strings
			// Ej: {"level": "50", "max": "100"} después del WALK
			if strVal, ok := supplyMap[key].(string); ok && strVal != "" {
				var intResult int
				if _, err := fmt.Sscanf(strVal, "%d", &intResult); err == nil {
					return intResult
				}
				// Intentar parsearlo como float primero si tiene decimales
				var floatResult float64
				if _, err := fmt.Sscanf(strVal, "%f", &floatResult); err == nil {
					return int(floatResult)
				}
			}
		}
	}

	return 0
}

func (b *Builder) normalizeToID(name string) string {
	// Convertir "Black Toner" → "toner_black"
	// Implementación simple por ahora
	return strings.ToLower(strings.ReplaceAll(name, " ", "_"))
}

func (b *Builder) extractColorCapability(data *collector.PrinterData) bool {
	// Detectar color capability basado en:
	// 1. Presencia de supplies de color (cyan, magenta, yellow, color ink)
	// 2. Color pages counter > 0
	// 3. Presencia de toner/ink para colores

	// Chequeo 1: Supplies
	if len(data.Supplies) > 0 {
		for _, supply := range data.Supplies {
			// Extraer tipo de supply usando helper function
			supplyType := b.extractFieldAsString(supply, "type", "description", "name")
			supplyType = strings.ToLower(supplyType)
			if strings.Contains(supplyType, "cyan") ||
				strings.Contains(supplyType, "magenta") ||
				strings.Contains(supplyType, "yellow") ||
				strings.Contains(supplyType, "color") {
				return true
			}
		}
	}

	// Chequeo 2: NormalizedCounters color_pages
	if data.NormalizedCounters != nil {
		if colorPages, ok := data.NormalizedCounters["color_pages"]; ok {
			switch v := colorPages.(type) {
			case int:
				if v > 0 {
					return true
				}
			case int64:
				if v > 0 {
					return true
				}
			case float64:
				if int64(v) > 0 {
					return true
				}
			}
		}
	}

	// Chequeo 3: Counters
	if data.Counters != nil {
		for key := range data.Counters {
			if strings.Contains(strings.ToLower(key), "color") {
				return true
			}
		}
	}

	return false
}

// extractSerialFromDescription extrae el número de serie de una descripción
// Soporta formatos: "S/N:XXXX", "SN:XXXX", "Serial:XXXX", ";SNXXXX", "S/N: XXXX"
func (b *Builder) extractSerialFromDescription(desc string) string {
	descUpper := strings.ToUpper(desc)

	// Formato Xerox: "PN 006R01509;SN99172880E000044B"
	if idx := strings.Index(descUpper, ";SN"); idx != -1 {
		serial := desc[idx+3:]
		serial = strings.TrimSpace(serial)
		serial = strings.TrimSuffix(serial, "unknown")
		serial = strings.TrimSpace(serial)
		if serial != "" && len(serial) > 2 {
			return serial
		}
	}

	// Formato Samsung/ISO: "S/N:CRUM-24030716547"
	for _, pattern := range []string{"S/N:", "SN:", "Serial:", "serial:"} {
		if idx := strings.Index(descUpper, strings.ToUpper(pattern)); idx != -1 {
			serial := desc[idx+len(pattern):]
			serial = strings.TrimSpace(serial)
			if serial != "" && len(serial) > 2 {
				return serial
			}
		}
	}

	return ""
}

// extractPartNumberFromDescription extrae el número de parte de una descripción
// Soporta formatos: "PN 006R01509", "PN: 006R01509", "P/N: 006R01509", "Model: XXXX"
func (b *Builder) extractPartNumberFromDescription(desc string) string {
	descUpper := strings.ToUpper(desc)

	// Formato Xerox: "Black Toner, PN 006R01509;SN..."
	for _, pattern := range []string{"PN ", "PN:", "P/N:", "P/N ", "PartNumber:", "Part Number:"} {
		if idx := strings.Index(descUpper, strings.ToUpper(pattern)); idx != -1 {
			partNum := desc[idx+len(pattern):]
			partNum = strings.TrimSpace(partNum)
			// Extraer hasta el próximo delimitador
			for _, delim := range []string{";", ",", " S/N", " SN:", "Serial"} {
				if delimIdx := strings.Index(strings.ToUpper(partNum), strings.ToUpper(delim)); delimIdx != -1 {
					partNum = partNum[:delimIdx]
					break
				}
			}
			partNum = strings.TrimSpace(partNum)
			if partNum != "" && len(partNum) > 2 && partNum != "unknown" {
				return partNum
			}
		}
	}

	return ""
}
