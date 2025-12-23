package normalizer

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/asaavedra/agent-snmp/pkg/collector"
)

// Normalize refactorizado con arquitectura profesional
func Normalize(raw collector.PrinterData) *NormalizedPrinter {
	normalized := &NormalizedPrinter{
		IP:              raw.IP,
		Brand:           raw.Brand,
		BrandConfidence: raw.Confidence,
		Timestamp:       raw.Timestamp.Format("2006-01-02T15:04:05Z"),
		AdminInfo:       raw.AdminInfo,
		Metadata: &Metadata{
			ResponseTimeMs: raw.ResponseTime.Milliseconds(),
			ProbeAttempts:  raw.ProbeAttempts,
		},
		UnsupportedFields: []string{},
		RealErrors:        []string{},
		MissingSections:   []string{},
	}

	// Clasificar errores: reales vs unsupported
	classifyErrors(raw, normalized)

	// Normalizar por marca
	switch raw.Brand {
	case "HP":
		normalizeHPProto(raw, normalized)
	case "Xerox":
		normalizeXeroxProto(raw, normalized)
	case "Brother":
		normalizeBrotherProto(raw, normalized)
	case "Ricoh":
		normalizeRicohProto(raw, normalized)
	case "Canon":
		normalizeCanonProto(raw, normalized)
	case "Samsung":
		normalizeSamsungProto(raw, normalized)
	default:
		normalizeGenericProto(raw, normalized)
	}

	// Evaluar status de probe
	evaluateProbeStatus(normalized)

	// Calcular cobertura de OIDs
	calculateOIDCoverage(normalized)

	return normalized
}

// calculateOIDCoverage calcula estadísticas de cobertura de OIDs
func calculateOIDCoverage(norm *NormalizedPrinter) {
	if norm.Metadata == nil {
		return
	}

	coverage := make(map[string]int)

	// Contar por source en identification
	if norm.Identification != nil {
		countOIDsBySource(norm.Identification.Model, coverage)
		countOIDsBySource(norm.Identification.SerialNumber, coverage)
		countOIDsBySource(norm.Identification.FirmwareVersion, coverage)
		countOIDsBySource(norm.Identification.Description, coverage)
	}

	// Contar por source en status
	if norm.Status != nil {
		countStatusOIDsBySource(norm.Status.GeneralStatus, coverage)
		countStatusOIDsBySource(norm.Status.OverallStatus, coverage)
		countStatusOIDsBySource(norm.Status.DoorStatus, coverage)
	}

	// Contar por source en supplies
	if norm.Supplies != nil {
		countSupplyOIDsBySource(norm.Supplies.TonerBlack, coverage)
		countSupplyOIDsBySource(norm.Supplies.TonerCyan, coverage)
		countSupplyOIDsBySource(norm.Supplies.TonerMagenta, coverage)
		countSupplyOIDsBySource(norm.Supplies.TonerYellow, coverage)
		countSupplyOIDsBySource(norm.Supplies.DrumUnit, coverage)
		countSupplyOIDsBySource(norm.Supplies.WasteContainer, coverage)
	}

	// Contar por source en counters
	if norm.Counters != nil {
		countOIDsBySource(norm.Counters.TotalPages, coverage)
		countOIDsBySource(norm.Counters.PagesBN, coverage)
		countOIDsBySource(norm.Counters.PagesColor, coverage)
		countOIDsBySource(norm.Counters.ColorPages, coverage)
	}

	norm.Metadata.OIDCoverage = coverage
}

// countOIDsBySource cuenta OIDs exitosos por su source
func countOIDsBySource(val *DataValue, coverage map[string]int) {
	if val == nil || val.Value == nil {
		return
	}
	if val.Source != "" {
		coverage[val.Source]++
	}
}

// countStatusOIDsBySource cuenta status OIDs por su source
func countStatusOIDsBySource(val *StatusCode, coverage map[string]int) {
	if val == nil {
		return
	}
	if val.OID != "" {
		// Determinar source desde el OID
		source := "unknown_oid"
		if isStandardOID(val.OID) {
			source = "standard_oid"
		} else if isVendorOID(val.OID) {
			source = "vendor_oid"
		}
		coverage[source]++
	}
}

// countSupplyOIDsBySource cuenta supply OIDs por su source
func countSupplyOIDsBySource(val *SupplyLevel, coverage map[string]int) {
	if val == nil || val.Value == 0 {
		return
	}
	if val.Source != "" {
		coverage[val.Source]++
	}
}

// isStandardOID detecta si es un OID estándar (1.3.6.1.2.1.*)
func isStandardOID(oid string) bool {
	return len(oid) > 9 && oid[:9] == "1.3.6.1.2"
}

// isVendorOID detecta si es un OID propietario (1.3.6.1.4.1.*)
func isVendorOID(oid string) bool {
	return len(oid) > 11 && oid[:11] == "1.3.6.1.4.1"
}

// classifyErrors separa errores reales de campos no soportados
func classifyErrors(raw collector.PrinterData, norm *NormalizedPrinter) {
	unsupportedByBrand := getUnsupportedFieldsByBrand(raw.Brand)

	for _, err := range raw.Errors {
		// Los errores que empiezan con "missing:" son campos no encontrados
		if strings.HasPrefix(err, "missing:") {
			fieldName := strings.TrimPrefix(err, "missing:")

			// Si es un campo no soportado por la marca, agregarlo a unsupported
			if _, isUnsupported := unsupportedByBrand[fieldName]; isUnsupported {
				norm.UnsupportedFields = append(norm.UnsupportedFields, fieldName)
			} else {
				// Si no se sabe, es un error real
				norm.RealErrors = append(norm.RealErrors, err)
			}
		} else if strings.Contains(err, "timeout") || strings.Contains(err, "unreachable") {
			// Errores reales de comunicación
			norm.RealErrors = append(norm.RealErrors, err)
			norm.Metadata.TimeoutEncoded = true
		}
	}
}

// getUnsupportedFieldsByBrand define qué campos NO soporta cada marca
func getUnsupportedFieldsByBrand(brand string) map[string]bool {
	unsupported := map[string]bool{}

	switch brand {
	case "Samsung":
		// Samsung muchas veces no expone estos OIDs estándar
		unsupported = map[string]bool{
			"serialNumber":          true,
			"firmwareVersion":       true,
			"printerStatus":         true,
			"tonerBlackPercent":     true, // Samsung usa Alt
			"tonerCyanPercent":      true,
			"drumPercent":           true,
			"totalPages":            true, // Samsung usa Alt
			"doorStatus":            true,
			"overallStatus":         true,
			"tonerMagentaPercent":   true,
			"tonerYellowPercent":    true,
			"wasteContainerPercent": true,
		}
	case "Xerox":
		unsupported = map[string]bool{
			"model":           true, // Xerox usa modelAlt
			"serialNumber":    true, // Usa serialNumberAlt
			"firmwareVersion": true,
			"totalPages":      true, // Usa totalPagesAlt
		}
	case "Generic":
		unsupported = map[string]bool{
			"serialNumber":        true,
			"firmwareVersion":     true,
			"doorStatus":          true,
			"tonerMagentaPercent": true,
			"tonerYellowPercent":  true,
			"drumPercent":         true,
		}
	}

	return unsupported
}

// detectMissingSections llena missingSections automáticamente
func detectMissingSections(norm *NormalizedPrinter) {
	sections := []struct {
		name  string
		check func() bool
	}{
		{"status", func() bool {
			return norm.Status == nil || (norm.Status.GeneralStatus == nil && norm.Status.OverallStatus == nil)
		}},
		{"supplies", func() bool {
			return norm.Supplies == nil || (norm.Supplies.TonerBlack == nil && norm.Supplies.DrumUnit == nil && norm.Supplies.WasteContainer == nil)
		}},
		{"counters", func() bool { return norm.Counters == nil || norm.Counters.TotalPages == nil }},
		{"identification", func() bool {
			return norm.Identification == nil || (norm.Identification.Model == nil && norm.Identification.SerialNumber == nil)
		}},
	}

	for _, section := range sections {
		if section.check() {
			norm.MissingSections = append(norm.MissingSections, section.name)
		}
	}
}

// evaluateProbeStatus determina si fue éxito, lento, parcial o fallo
func evaluateProbeStatus(norm *NormalizedPrinter) {
	if len(norm.RealErrors) > 0 {
		norm.Metadata.ProbeStatus = "failed"
		return
	}

	if norm.Metadata.TimeoutEncoded || norm.Metadata.ResponseTimeMs > 5000 {
		norm.Metadata.ProbeStatus = "slow"
		norm.Metadata.PartialData = true
		return
	}

	if len(norm.MissingSections) > 0 {
		norm.Metadata.ProbeStatus = "partial"
		norm.Metadata.PartialData = true
		return
	}

	norm.Metadata.ProbeStatus = "success"
}

// normalizeSamsungProto - Samsung con lógica de unidades y OIDs
func normalizeSamsungProto(raw collector.PrinterData, norm *NormalizedPrinter) {
	oids := GetOIDs("Samsung")

	norm.Identification = &IdentificationData{
		Description: CreateDataValueWithOID(raw.Identification["description"], "string", "standard_oid", 0.95, oids.Description),
		Model:       CreateDataValueWithOID(raw.Identification["model"], "string", "vendor_oid", 0.90, oids.Model),
	}

	norm.Status = &StatusData{
		GeneralStatus: DecodeStatusWithOID(raw.Status["generalStatus"], oids.GeneralStatus),
	}

	// Samsung: usar Alt con inferencia de unidad
	supplies := &SuppliesData{}

	// Toner Black - preferir tonerBlackPercentAlt
	if rawVal, ok := raw.Supplies["tonerBlackPercentAlt"]; ok && rawVal != nil {
		supplies.TonerBlack = CreateSupplyWithOID(rawVal, "alt_oid", raw.Supplies, oids.TonerBlackAlt)
	} else if rawVal, ok := raw.Supplies["tonerBlackPercent"]; ok && rawVal != nil {
		supplies.TonerBlack = CreateSupplyWithOID(rawVal, "vendor_oid", raw.Supplies, oids.TonerBlackPercent)
	}

	// Procesar consumibles descubiertos via WALK
	processDynamicSupplies(raw, supplies)

	norm.Supplies = supplies

	// Counters - Samsung con pagesBN/pagesColor
	counters := &CountersData{}
	if rawVal, ok := raw.Counters["totalPagesAlt"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.TotalPages = CreateDataValueWithOID(valInt, "pages", "alt_oid", 0.90, oids.TotalPagesAlt)
	} else if rawVal, ok := raw.Counters["totalPages"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.TotalPages = CreateDataValueWithOID(valInt, "pages", "vendor_oid", 0.85, oids.TotalPages)
	}

	// PagesBN (si disponible)
	if rawVal, ok := raw.Counters["pagesBN"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.PagesBN = CreateDataValueWithOID(valInt, "pages", "vendor_oid", 0.90, oids.PagesBN)
	}

	// PagesColor (si disponible)
	if rawVal, ok := raw.Counters["pagesColor"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.PagesColor = CreateDataValueWithOID(valInt, "pages", "vendor_oid", 0.90, oids.PagesColor)
	}

	norm.Counters = counters
}

// normalizeXeroxProto - Xerox con pagesBN/pagesColor
func normalizeXeroxProto(raw collector.PrinterData, norm *NormalizedPrinter) {
	oids := GetOIDs("Xerox")

	norm.Identification = &IdentificationData{
		Description: CreateDataValueWithOID(raw.Identification["description"], "string", "standard_oid", 0.95, oids.Description),
		Model:       CreateDataValueWithOID(raw.Identification["modelAlt"], "string", "alt_oid", 0.85, oids.Model),
	}

	norm.Status = &StatusData{
		GeneralStatus: DecodeStatusWithOID(raw.Status["generalStatus"], oids.GeneralStatus),
		DoorStatus:    DecodeStatusWithOID(raw.Status["doorStatus"], ""),
	}

	// Supplies
	supplies := &SuppliesData{}
	if rawVal, ok := raw.Supplies["tonerBlackPercentAlt"]; ok && rawVal != nil {
		supplies.TonerBlack = CreateSupplyWithOID(rawVal, "alt_oid", raw.Supplies, oids.TonerBlackAlt)
	}

	// Procesar consumibles descubiertos via WALK
	processDynamicSupplies(raw, supplies)

	norm.Supplies = supplies

	// Counters con pagesBN/pagesColor
	counters := &CountersData{}
	if rawVal, ok := raw.Counters["totalPagesAlt"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.TotalPages = CreateDataValueWithOID(valInt, "pages", "alt_oid", 0.90, oids.TotalPagesAlt)
		counters.PagesBN = CreateDataValueWithOID(valInt, "pages", "alt_oid", 0.90, oids.PagesBN)
	} else if rawVal, ok := raw.Counters["totalPages"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.TotalPages = CreateDataValueWithOID(valInt, "pages", "vendor_oid", 0.85, oids.TotalPages)
	}

	// Xerox pagesColor (si está disponible)
	if rawVal, ok := raw.Counters["pagesColor"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.PagesColor = CreateDataValueWithOID(valInt, "pages", "vendor_oid", 0.90, oids.PagesColor)
	}

	norm.Counters = counters
}

// normalizeHPProto - HP con páginas BN/Color
func normalizeHPProto(raw collector.PrinterData, norm *NormalizedPrinter) {
	oids := GetOIDs("HP")

	norm.Identification = &IdentificationData{
		Model:           CreateDataValueWithOID(raw.Identification["model"], "string", "vendor_oid", 0.90, oids.Model),
		Description:     CreateDataValueWithOID(raw.Identification["description"], "string", "standard_oid", 0.95, oids.Description),
		SerialNumber:    CreateDataValueWithOID(raw.Identification["serialNumber"], "string", "vendor_oid", 0.88, oids.SerialNumber),
		FirmwareVersion: CreateDataValueWithOID(raw.Identification["firmwareVersion"], "string", "vendor_oid", 0.87, ""),
	}

	norm.Status = &StatusData{
		GeneralStatus: DecodeStatusWithOID(raw.Status["generalStatus"], oids.GeneralStatus),
		OverallStatus: DecodeStatusWithOID(raw.Status["overallStatus"], oids.OverallStatus),
	}

	supplies := &SuppliesData{}
	if rawVal, ok := raw.Supplies["tonerBlackPercent"]; ok && rawVal != nil {
		supplies.TonerBlack = CreateSupplyWithOID(rawVal, "vendor_oid", raw.Supplies, oids.TonerBlackPercent)
	}

	// Procesar consumibles descubiertos via WALK
	processDynamicSupplies(raw, supplies)

	norm.Supplies = supplies

	counters := &CountersData{}
	if rawVal, ok := raw.Counters["totalPages"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.TotalPages = CreateDataValueWithOID(valInt, "pages", "vendor_oid", 0.95, oids.TotalPages)
	} else if rawVal, ok := raw.Counters["totalPagesAlt"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.TotalPages = CreateDataValueWithOID(valInt, "pages", "alt_oid", 0.85, oids.TotalPagesAlt)
	}

	// HP pagesBN/pagesColor (vendor-specific)
	if rawVal, ok := raw.Counters["pagesBN"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.PagesBN = CreateDataValueWithOID(valInt, "pages", "vendor_oid", 0.95, oids.PagesBN)
	}

	if rawVal, ok := raw.Counters["pagesColor"]; ok && rawVal != nil {
		valInt := toIntHelper(rawVal)
		counters.PagesColor = CreateDataValueWithOID(valInt, "pages", "vendor_oid", 0.95, oids.PagesColor)
	}

	norm.Counters = counters
}

// normalizeBrotherProto
func normalizeBrotherProto(raw collector.PrinterData, norm *NormalizedPrinter) {
	norm.Identification = &IdentificationData{
		Description: CreateDataValue(raw.Identification["description"], "string", "standard_oid", 0.95),
	}

	norm.Status = &StatusData{
		GeneralStatus: DecodeStatus(raw.Status["generalStatus"]),
	}

	supplies := &SuppliesData{}
	processDynamicSupplies(raw, supplies)
	norm.Supplies = supplies
	norm.Counters = &CountersData{}
}

// normalizeRicohProto
func normalizeRicohProto(raw collector.PrinterData, norm *NormalizedPrinter) {
	norm.Identification = &IdentificationData{
		Description: CreateDataValue(raw.Identification["description"], "string", "standard_oid", 0.95),
	}

	norm.Status = &StatusData{
		GeneralStatus: DecodeStatus(raw.Status["generalStatus"]),
	}

	supplies := &SuppliesData{}
	processDynamicSupplies(raw, supplies)
	norm.Supplies = supplies
	norm.Counters = &CountersData{}
}

// normalizeCanonProto
func normalizeCanonProto(raw collector.PrinterData, norm *NormalizedPrinter) {
	norm.Identification = &IdentificationData{
		Description: CreateDataValue(raw.Identification["description"], "string", "standard_oid", 0.95),
	}

	norm.Status = &StatusData{
		GeneralStatus: DecodeStatus(raw.Status["generalStatus"]),
	}

	supplies := &SuppliesData{}
	processDynamicSupplies(raw, supplies)
	norm.Supplies = supplies
	norm.Counters = &CountersData{}
}

// normalizeGenericProto
func normalizeGenericProto(raw collector.PrinterData, norm *NormalizedPrinter) {
	norm.Identification = &IdentificationData{
		Description: CreateDataValue(raw.Identification["description"], "string", "standard_oid", 0.95),
	}

	norm.Status = &StatusData{
		GeneralStatus: DecodeStatus(raw.Status["hrDeviceStatus"]),
	}

	supplies := &SuppliesData{}
	processDynamicSupplies(raw, supplies)
	norm.Supplies = supplies
	norm.Counters = &CountersData{}
}

// Helper para conversión segura
func toIntHelper(val interface{}) int {
	if val == nil {
		return 0
	}

	switch v := val.(type) {
	case int:
		return v
	case string:
		if num, err := strconv.Atoi(v); err == nil {
			return num
		}
	case uint:
		return int(v)
	case uint32:
		return int(v)
	case uint64:
		return int(v)
	default:
		if num, err := strconv.Atoi(fmt.Sprintf("%v", v)); err == nil {
			return num
		}
	}

	return 0
}

// processDynamicSupplies procesa consumibles descubiertos via WALK
func processDynamicSupplies(raw collector.PrinterData, supplies *SuppliesData) {
	if supplies == nil {
		supplies = &SuppliesData{}
	}

	// Identificar consumibles WALK (los que tienen estructura con level/max via WALK)
	walkConsumibles := make(map[string]interface{})

	// OIDs que ya se procesan manualmente en los normalizadores
	handledKeys := map[string]bool{
		"tonerBlackPercent":     true,
		"tonerBlackPercentAlt":  true,
		"tonerCyanPercent":      true,
		"tonerMagentaPercent":   true,
		"tonerYellowPercent":    true,
		"drumPercent":           true,
		"wasteContainerPercent": true,
	}

	// Extraer consumibles dinámicos - INCLUYENDO los tonerXxx descobertos via WALK
	for key, val := range raw.Supplies {
		if handledKeys[key] {
			continue // Saltar los ya manejados
		}

		// Verificar si es un consumible descoberto via WALK (tiene oid_level)
		if mapVal, ok := val.(map[string]interface{}); ok {
			if _, hasOIDLevel := mapVal["oid_level"]; hasOIDLevel {
				walkConsumibles[key] = val
			}
		}
	}

	// Procesar consumibles WALK
	if len(walkConsumibles) > 0 {
		if supplies.DynamicSupplies == nil {
			supplies.DynamicSupplies = make(map[string]*SupplyLevel)
		}

		for key, val := range walkConsumibles {
			if mapVal, ok := val.(map[string]interface{}); ok {
				// Extraer level y max
				levelStr := ""
				maxStr := ""

				if level, ok := mapVal["level"]; ok {
					levelStr = fmt.Sprintf("%v", level)
				}
				if max, ok := mapVal["max"]; ok {
					maxStr = fmt.Sprintf("%v", max)
				}

				if levelStr != "" {
					levelVal := toInt(levelStr)
					maxVal := 100 // Default

					if maxStr != "" {
						maxVal = toInt(maxStr)
					}

					// Calcular porcentaje si tenemos max
					percentage := 0
					if maxVal > 0 {
						percentage = (levelVal * 100) / maxVal
					}

					// Inferir unidad
					unit := "percent"
					if maxVal > 1000 {
						unit = "pages_remaining"
					}

					// OID
					oidLevel := ""
					if oidLevelVal, ok := mapVal["oid_level"]; ok {
						oidLevel = fmt.Sprintf("%v", oidLevelVal)
					}

					supplies.DynamicSupplies[key] = &SupplyLevel{
						Value:      percentage,
						Unit:       unit,
						Confidence: 0.80,
						Status:     "ok",
						Source:     "discovered_via_walk",
						OID:        oidLevel,
					}
				}
			}
		}
	}
}
