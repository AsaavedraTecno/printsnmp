package profile

import (
	"fmt"
	"strconv"
	"time"

	"github.com/asaavedra/agent-snmp/pkg/snmp"
)

// ConsistencyChecker valida que los OIDs devuelven valores consistentes
type ConsistencyChecker struct {
	client    *snmp.SNMPClient
	attempts  int           // Cuántos polls hacer (default: 3)
	interval  time.Duration // Delay entre polls (default: 100ms)
	tolerance float64       // Tolerancia en variación (default: 0.1 = 10%)
}

// NewConsistencyChecker crea un nuevo validador de consistencia
func NewConsistencyChecker(client *snmp.SNMPClient) *ConsistencyChecker {
	return &ConsistencyChecker{
		client:    client,
		attempts:  3,
		interval:  100 * time.Millisecond,
		tolerance: 0.10, // 10% de variación tolerada
	}
}

// CheckConsistency verifica si un OID devuelve valores consistentes
// Retorna (isConsistent, meanValue, metadata, error)
func (cc *ConsistencyChecker) CheckConsistency(oid string) (bool, float64, *OIDMetadata, error) {
	ctx := snmp.NewContext()
	var values []float64

	// Hacer múltiples polls del mismo OID
	for i := 0; i < cc.attempts; i++ {
		if i > 0 {
			time.Sleep(cc.interval)
		}

		result, err := cc.client.Get(oid, ctx)
		if err != nil {
			continue
		}

		// Convertir valor a float64 si es posible
		if floatVal, ok := cc.parseToFloat(result); ok {
			values = append(values, floatVal)
		}
	}

	// Si no tuvimos al menos 2 valores exitosos, no podemos validar
	if len(values) < 2 {
		return len(values) > 0, 0, nil, fmt.Errorf("insuficientes polls exitosos: %d", len(values))
	}

	// Calcular estadísticas
	meanVal := cc.calculateMean(values)
	isConsistent := cc.isValuesConsistent(values, meanVal)

	// Crear metadata
	metadata := &OIDMetadata{
		OID:        oid,
		LastValue:  values[len(values)-1],
		MeanValue:  meanVal,
		Consistent: isConsistent,
	}

	return isConsistent, meanVal, metadata, nil
}

// CheckMultipleOIDs valida consistencia de múltiples OIDs en paralelo
func (cc *ConsistencyChecker) CheckMultipleOIDs(oids []string) map[string]*OIDMetadata {
	results := make(map[string]*OIDMetadata)

	for _, oid := range oids {
		isConsistent, _, metadata, err := cc.CheckConsistency(oid)
		if err == nil && isConsistent {
			metadata.Consistent = true
			results[oid] = metadata
		}
	}

	return results
}

// parseToFloat intenta convertir un valor a float64
func (cc *ConsistencyChecker) parseToFloat(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	case string:
		floatVal, err := strconv.ParseFloat(v, 64)
		return floatVal, err == nil
	default:
		return 0, false
	}
}

// calculateMean calcula el promedio de los valores
func (cc *ConsistencyChecker) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, v := range values {
		sum += v
	}

	return sum / float64(len(values))
}

// isValuesConsistent verifica si los valores son consistentes
func (cc *ConsistencyChecker) isValuesConsistent(values []float64, mean float64) bool {
	if mean == 0 {
		// Para valores cercanos a cero, usar tolerancia absoluta
		for _, v := range values {
			if v > 0.5 { // Si algún valor es > 0.5, hay inconsistencia
				return false
			}
		}
		return true
	}

	// Para otros valores, usar tolerancia porcentual
	for _, v := range values {
		variation := (v - mean) / mean
		if variation < 0 {
			variation = -variation
		}

		if variation > cc.tolerance {
			return false
		}
	}

	return true
}

// IsCounterOID detecta si un OID es un contador (siempre igual o crece)
func (cc *ConsistencyChecker) IsCounterOID(oid string) bool {
	ctx := snmp.NewContext()
	var values []float64

	// Poll 3 veces
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}

		result, err := cc.client.Get(oid, ctx)
		if err != nil {
			continue
		}

		if floatVal, ok := cc.parseToFloat(result); ok {
			values = append(values, floatVal)
		}
	}

	if len(values) < 2 {
		return false
	}

	// Un contador debe ser igual o crecer, nunca decrecer
	for i := 1; i < len(values); i++ {
		if values[i] < values[i-1] {
			return false
		}
	}

	return true
}

// IsSupplyOID detecta si un OID es un consumible (0-100%)
func (cc *ConsistencyChecker) IsSupplyOID(oid string) bool {
	ctx := snmp.NewContext()
	var values []float64

	// Poll 3 veces
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}

		result, err := cc.client.Get(oid, ctx)
		if err != nil {
			continue
		}

		if floatVal, ok := cc.parseToFloat(result); ok {
			values = append(values, floatVal)
		}
	}

	if len(values) == 0 {
		return false
	}

	// Un consumible debe estar entre 0 y 100
	for _, v := range values {
		if v < 0 || v > 100 {
			return false
		}
	}

	return true
}
