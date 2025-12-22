package normalizer

import (
	"fmt"
	"strconv"
	"strings"
)

// DecodeStatus decodifica códigos numéricos de estado SNMP
func DecodeStatus(code interface{}) *StatusCode {
	return DecodeStatusWithOID(code, "")
}

// DecodeStatusWithOID decodifica códigos numéricos de estado SNMP con OID
func DecodeStatusWithOID(code interface{}, oid string) *StatusCode {
	if code == nil {
		return nil
	}

	codeInt := 0
	switch v := code.(type) {
	case int:
		codeInt = v
	case string:
		if num, err := strconv.Atoi(v); err == nil {
			codeInt = num
		} else {
			return nil
		}
	case uint:
		codeInt = int(v)
	default:
		return nil
	}

	// Mapear códigos HR-MIB estándar
	meaning := ""
	details := ""

	switch codeInt {
	case 1:
		meaning = "other"
		details = "Device state is unknown or other"
	case 2:
		meaning = "idle"
		details = "Device is idle"
	case 3:
		meaning = "ready"
		details = "Device is ready"
	case 4:
		meaning = "printing"
		details = "Device is printing"
	case 5:
		meaning = "error"
		details = "Device has an error"
	case 6:
		meaning = "offline"
		details = "Device is offline"
	default:
		meaning = "unknown"
		details = fmt.Sprintf("Unknown state code: %d", codeInt)
	}

	return &StatusCode{
		Code:    codeInt,
		Meaning: meaning,
		Details: details,
		OID:     oid,
	}
}

// InferSupplyUnit intenta inferir la unidad de un valor de consumible
func InferSupplyUnit(value interface{}, oidsPresent map[string]interface{}) (string, float64) {
	if value == nil {
		return "unknown", 0.0
	}

	valInt := toInt(value)
	if valInt < 0 {
		return "unknown", 0.0
	}

	// Si el valor está entre 0-100, probablemente sea porcentaje
	if valInt <= 100 {
		return "percent", float64(valInt)
	}

	// Si está entre 100-10000, probablemente sea páginas restantes
	if valInt > 100 && valInt <= 1000000 {
		// Para Samsung/Xerox típicamente es páginas * 100
		if valInt > 10000 {
			return "pages_remaining", float64(valInt / 100)
		}
		return "pages_remaining", float64(valInt)
	}

	// Si es muy grande, es raw counter interno
	if valInt > 1000000 {
		return "raw_counter", float64(valInt)
	}

	return "raw", float64(valInt)
}

// ConfidenceSupply calcula confianza en base a la unidad inferida
func ConfidenceSupply(unit string) float64 {
	switch unit {
	case "percent":
		return 0.95 // Muy confiable
	case "pages_remaining":
		return 0.85 // Confiable pero necesita normalización
	case "pages":
		return 0.90
	case "raw_counter":
		return 0.50 // Poco confiable sin contexto
	default:
		return 0.30 // Muy poco confiable
	}
}

// ConvertToPercent intenta convertir valores a porcentaje
func ConvertToPercent(value interface{}, unit string) int {
	valInt := toInt(value)

	switch unit {
	case "percent":
		if valInt > 100 {
			return 100
		}
		if valInt < 0 {
			return 0
		}
		return valInt
	case "pages_remaining":
		// Asumir 100 páginas = 1%
		percent := valInt / 100
		if percent > 100 {
			return 100
		}
		if percent < 0 {
			return 0
		}
		return percent
	default:
		return 0
	}
}

// CreateDataValue crea un DataValue con metadatos
func CreateDataValue(value interface{}, unit string, source string, confidence float64) *DataValue {
	return CreateDataValueWithOID(value, unit, source, confidence, "")
}

// CreateDataValueWithOID crea un DataValue incluyendo OID
func CreateDataValueWithOID(value interface{}, unit string, source string, confidence float64, oid string) *DataValue {
	if value == nil {
		return nil
	}

	valStr := fmt.Sprintf("%v", value)
	if valStr == "" {
		return nil
	}

	return &DataValue{
		Value:      value,
		Unit:       unit,
		Source:     source,
		Confidence: confidence,
		OID:        oid,
	}
}

// CreateSupply crea un SupplyLevel con lógica inteligente e incluye OID
func CreateSupply(value interface{}, source string, oidsContext map[string]interface{}) *SupplyLevel {
	return CreateSupplyWithOID(value, source, oidsContext, "")
}

// CreateSupplyWithOID crea un SupplyLevel incluyendo OID específico
func CreateSupplyWithOID(value interface{}, source string, oidsContext map[string]interface{}, oid string) *SupplyLevel {
	if value == nil {
		return nil
	}

	valInt := toInt(value)
	unit, _ := InferSupplyUnit(value, oidsContext)
	confidence := ConfidenceSupply(unit)

	// Determinar status
	status := "ok"
	percentVal := ConvertToPercent(value, unit)

	if percentVal < 20 {
		status = "warning"
	}
	if percentVal < 5 {
		status = "critical"
	}

	return &SupplyLevel{
		Value:      valInt,
		Unit:       unit,
		Confidence: confidence,
		Status:     status,
		Source:     source,
		OID:        oid,
	}
}

// Helpers
func toInt(val interface{}) int {
	switch v := val.(type) {
	case int:
		return v
	case uint:
		return int(v)
	case uint32:
		return int(v)
	case uint64:
		return int(v)
	case string:
		if num, err := strconv.Atoi(v); err == nil {
			return num
		}
	default:
		if num, err := strconv.Atoi(fmt.Sprintf("%v", v)); err == nil {
			return num
		}
	}
	return 0
}

func toString(val interface{}) string {
	if val == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", val))
}
