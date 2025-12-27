package profile

import (
	"fmt"
	"strings"
	"time"

	"github.com/asaavedra/agent-snmp/pkg/snmp"
)

// Discoverer ejecuta un WALK estratégico y clasifica OIDs
type Discoverer struct {
	client *snmp.SNMPClient
}

// NewDiscoverer crea un nuevo descubridor de OIDs
func NewDiscoverer(client *snmp.SNMPClient) *Discoverer {
	return &Discoverer{client: client}
}

// DiscoverProfile ejecuta WALK estratégico y retorna un nuevo perfil
func (d *Discoverer) DiscoverProfile(ip, brand, model, serialNumber string) (*Profile, error) {
	profile := &Profile{
		PrinterID:         ip,
		IP:                ip,
		Brand:             brand,
		Model:             model,
		OIDs:              make(map[string][]string),
		OIDMetadata:       make(map[string]OIDMetadata),
		OIDFriendlyNames:  make(map[string]string),
		Capabilities:      CapabilityMap{},
		DiscoveredAt:      time.Now(),
		SNMPVersion:       "2c",
		DiscoveryAttempts: 1,
	}

	// PASO 1: WALK estratégico
	allWalkResults := d.walkStrategic()

	// PASO 2: Clasificar OIDs y filtrar inválidos
	d.classifyOIDs(profile, allWalkResults)

	// PASO 3: Enriquecer con metadata y nombres legibles
	d.enrichProfile(profile)

	// PASO 4: Generar mappings de contadores
	if len(profile.OIDs[string(CatCounters)]) > 0 {
		profile.CounterMappings = d.generateCounterMappings(brand, profile.OIDs[string(CatCounters)])
	}

	// PASO 5: Detectar capacidades
	d.detectCapabilities(profile)

	return profile, nil
}

// walkStrategic ejecuta WALK en árboles clave
func (d *Discoverer) walkStrategic() map[string][]snmp.WalkResult {
	trees := []struct {
		oid  string
		name string
	}{
		{"1.3.6.1.2.1.1", "system"},
		{"1.3.6.1.2.1.43", "printer-mib"},
		{"1.3.6.1.2.1.25", "host-resources"},
		{"1.3.6.1.4.1.11", "enterprise-hp"},
		{"1.3.6.1.4.1.253", "enterprise-xerox"},
		{"1.3.6.1.4.1.236", "enterprise-samsung"},
		{"1.3.6.1.4.1.367", "enterprise-ricoh"},
	}

	ctx := snmp.NewContext()
	results := make(map[string][]snmp.WalkResult)

	for _, tree := range trees {
		walkResults, err := d.client.Walk(tree.oid, ctx)
		if err != nil {
			continue
		}

		if len(walkResults) > 0 {
			results[tree.name] = walkResults
		}
	}

	return results
}

// classifyOIDs clasifica OIDs en categorías
func (d *Discoverer) classifyOIDs(profile *Profile, allResults map[string][]snmp.WalkResult) {
	oidsByCategory := make(map[OIDCategory][]string)

	for _, walkList := range allResults {
		for _, result := range walkList {
			// Validar que el valor sea útil
			if !isUsefulOID(result.OID, result.Value) {
				continue
			}

			// Clasificar el OID
			category := ClassifyOID(result.OID)

			// Evitar duplicados
			if !contains(oidsByCategory[category], result.OID) {
				oidsByCategory[category] = append(oidsByCategory[category], result.OID)
			}
		}
	}

	// Guardar OIDs por categoría
	for category, oids := range oidsByCategory {
		if len(oids) > 0 {
			profile.OIDs[string(category)] = oids
		}
	}

	logDiscovery(profile, oidsByCategory)
}

// detectCapabilities detecta capacidades basadas en OIDs encontrados
func (d *Discoverer) detectCapabilities(profile *Profile) {
	profile.Capabilities.Supplies = len(profile.OIDs[string(CatSupplies)]) > 0
	profile.Capabilities.Counters = len(profile.OIDs[string(CatCounters)]) > 0
	profile.Capabilities.Status = len(profile.OIDs[string(CatStatus)]) > 0
	profile.Capabilities.Network = len(profile.OIDs[string(CatNetwork)]) > 0
	profile.Capabilities.Color = true
	profile.Capabilities.Duplex = true
}

// isUsefulOID determina si un OID tiene valor útil
func isUsefulOID(_ string, value string) bool {
	// Rechazar valores vacíos y strings especiales
	if value == "" || value == "unknown" || value == "null" || value == "nil" {
		return false
	}

	// Rechazar valores centinela que indican error o no aplicable
	if value == "-1" || value == "-2" {
		return false
	}

	return true
}

// logDiscovery imprime resumen de descubrimiento
func logDiscovery(profile *Profile, oidsByCategory map[OIDCategory][]string) {
	fmt.Printf("[DISCOVERY] %s: ", profile.PrinterID)

	var parts []string
	if oids, ok := oidsByCategory[CatSupplies]; ok && len(oids) > 0 {
		parts = append(parts, fmt.Sprintf("%d supplies", len(oids)))
	}
	if oids, ok := oidsByCategory[CatCounters]; ok && len(oids) > 0 {
		parts = append(parts, fmt.Sprintf("%d counters", len(oids)))
	}
	if oids, ok := oidsByCategory[CatStatus]; ok && len(oids) > 0 {
		parts = append(parts, fmt.Sprintf("%d status", len(oids)))
	}
	if oids, ok := oidsByCategory[CatNetwork]; ok && len(oids) > 0 {
		parts = append(parts, fmt.Sprintf("%d network", len(oids)))
	}
	if oids, ok := oidsByCategory[CatSystem]; ok && len(oids) > 0 {
		parts = append(parts, fmt.Sprintf("%d system", len(oids)))
	}
	if oids, ok := oidsByCategory[CatVendor]; ok && len(oids) > 0 {
		parts = append(parts, fmt.Sprintf("%d vendor", len(oids)))
	}

	if len(parts) == 0 {
		fmt.Printf("No useful OIDs found\n")
		return
	}

	fmt.Printf("%s\n", strings.Join(parts, ", "))
}

// ClassifyOID clasifica un OID
func ClassifyOID(oid string) OIDCategory {
	oidLower := strings.ToLower(oid)

	if strings.Contains(oidLower, ".43.11") ||
		strings.Contains(oidLower, ".11.2.3.9.4.3") ||
		strings.Contains(oidLower, ".253.8.53.13") ||
		strings.Contains(oidLower, ".236.11.5.11") ||
		strings.Contains(oidLower, ".367.3.2") {
		return CatSupplies
	}

	if strings.Contains(oidLower, ".43.10") ||
		strings.Contains(oidLower, ".43.4") ||
		strings.Contains(oidLower, ".11.2.3.9.4.2") ||
		strings.Contains(oidLower, ".253.8.53.3") ||
		strings.Contains(oidLower, ".236.11.5.1") {
		return CatCounters
	}

	if strings.Contains(oidLower, ".25.3.2.1.5") ||
		strings.Contains(oidLower, ".43.13") ||
		strings.Contains(oidLower, ".43.5") ||
		strings.Contains(oidLower, ".11.2.3.9.4.2.1.5") {
		return CatStatus
	}

	if strings.Contains(oidLower, ".2.1.4") ||
		strings.Contains(oidLower, ".2.1.6") ||
		strings.Contains(oidLower, ".2.1.2") {
		return CatNetwork
	}

	if strings.Contains(oidLower, ".2.1.1") ||
		strings.Contains(oidLower, ".1.3.0") ||
		strings.Contains(oidLower, ".1.6.0") ||
		strings.Contains(oidLower, ".1.4.0") {
		return CatSystem
	}

	return CatVendor
}

// generateCounterMappings genera mappings de OIDs a nombres de contadores
func (d *Discoverer) generateCounterMappings(_ string, counterOIDs []string) map[string]string {
	mappings := make(map[string]string)

	standardMappings := map[string]string{
		"1.3.6.1.2.1.43.10.2.1.4.1.1": "total_pages",
		"1.3.6.1.2.1.43.10.2.1.4.1.2": "mono_pages",
		"1.3.6.1.2.1.43.10.2.1.4.1.3": "color_pages",
		"1.3.6.1.2.1.43.10.2.1.4.1.4": "scan_pages",
		"1.3.6.1.2.1.43.10.2.1.4.1.5": "copy_pages",
		"1.3.6.1.2.1.43.10.2.1.4.1.6": "fax_pages",
	}

	for _, oid := range counterOIDs {
		normalizedOID := strings.TrimPrefix(oid, ".")
		if mapping, ok := standardMappings[oid]; ok {
			mappings[oid] = mapping
		} else if mapping, ok := standardMappings[normalizedOID]; ok {
			mappings[normalizedOID] = mapping
		}
	}

	return mappings
}

// contains verifica si un slice contiene un elemento
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// enrichProfile enriquece el perfil con metadata y nombres amigables
func (d *Discoverer) enrichProfile(profile *Profile) {
	resolver := NewFriendlyNameResolver()

	for _, oidList := range profile.OIDs {
		for _, oid := range oidList {
			// Nombre amigable
			friendlyName := resolver.GetFriendlyName(oid)
			profile.OIDFriendlyNames[oid] = friendlyName

			// Metadata básica
			objType := resolver.DetectOIDType(friendlyName)
			unit := resolver.GetUnit(friendlyName)

			metadata := OIDMetadata{
				OID:        oid,
				Category:   ClassifyOID(oid),
				DataType:   "string",
				Unit:       unit,
				Consistent: false,
			}

			// Detectar rangos según tipo
			switch objType {
			case "supplies":
				metadata.MinValue = 0
				metadata.MaxValue = 100
				metadata.Unit = "%"
				metadata.DataType = "integer"
			case "counter":
				metadata.MinValue = 0
				metadata.DataType = "integer"
			}

			profile.OIDMetadata[oid] = metadata
		}
	}
}
