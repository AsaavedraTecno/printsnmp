package profile

import "time"

// Profile almacena el conocimiento de una impresora específica
// Una impresora = Un perfil
// Basado en: serial_number o printer_id
type Profile struct {
	// Identificación (inmutable después de creación)
	PrinterID string `json:"printer_id"` // SEC30CDA7C72268-ZDBQBJCH500055B
	IP        string `json:"ip"`
	Brand     string `json:"brand"` // HP, Samsung, Xerox, etc
	Model     string `json:"model"` // M428, CLP-365, AltaLink C8055

	// OIDs descubiertos (por categoría)
	OIDs map[string][]string `json:"oids"` // supplies, counters, status, etc

	// Mappings de OIDs a nombres de contadores (específico del modelo)
	// Ej: "1.3.6.1.2.1.43.10.2.1.4.1.1" -> "total_pages"
	CounterMappings map[string]string `json:"counter_mappings,omitempty"`

	// Metadata de OIDs (rangos, unidades, tipos de dato, consistencia)
	OIDMetadata map[string]OIDMetadata `json:"oid_metadata,omitempty"`

	// Nombres legibles para OIDs
	OIDFriendlyNames map[string]string `json:"oid_friendly_names,omitempty"`

	// Capacidades detectadas
	Capabilities CapabilityMap `json:"capabilities"`

	// Metadata
	DiscoveredAt    time.Time `json:"discovered_at"`
	LastValidatedAt time.Time `json:"last_validated_at"`
	FirmwareVersion string    `json:"firmware_version"`
	SNMPVersion     string    `json:"snmp_version"`

	// Historial
	DiscoveryAttempts int     `json:"discovery_attempts"`
	LastError         string  `json:"last_error,omitempty"`
	ErrorCount        int     `json:"error_count"`
	SuccessRate       float64 `json:"success_rate"` // 0.0-1.0
}

// CapabilityMap almacena qué capacidades tiene la impresora
type CapabilityMap struct {
	Duplex    bool     `json:"duplex"`
	Color     bool     `json:"color"`
	Scanner   bool     `json:"scanner"`
	Fax       bool     `json:"fax"`
	Supplies  bool     `json:"supplies"`
	Counters  bool     `json:"counters"`
	Network   bool     `json:"network"`
	Status    bool     `json:"status"`
	Supported []string `json:"supported_oids"` // Categorías que respondieron
	Failed    []string `json:"failed_oids"`    // Categorías que fallaron
}

// OIDCategory representa una categoría de OID
type OIDCategory string

const (
	CatSupplies OIDCategory = "supplies"
	CatCounters OIDCategory = "counters"
	CatStatus   OIDCategory = "status"
	CatNetwork  OIDCategory = "network"
	CatSystem   OIDCategory = "system"
	CatVendor   OIDCategory = "vendor"
)

// WalkResult representa un resultado del WALK estratégico
type WalkResult struct {
	OID      string
	Value    string
	Category OIDCategory // Deducida por el classifier
}

// OIDMetadata almacena información sobre un OID específico
type OIDMetadata struct {
	OID        string      `json:"oid"`
	Category   OIDCategory `json:"category"`
	MinValue   interface{} `json:"min_value,omitempty"`  // Ej: 0 para consumibles
	MaxValue   interface{} `json:"max_value,omitempty"`  // Ej: 100 para consumibles
	Unit       string      `json:"unit,omitempty"`       // "%", "pages", "sheets"
	DataType   string      `json:"data_type"`            // "integer", "string", "hex"
	LastValue  interface{} `json:"last_value,omitempty"` // Último valor leído
	Consistent bool        `json:"consistent,omitempty"` // Pasó validación de consistencia
	MeanValue  float64     `json:"mean_value,omitempty"` // Promedio de valores en consistency check
}

// OIDClassification es el resultado de clasificar y enriquecer un OID
type OIDClassification struct {
	OID          string
	Value        string
	Category     OIDCategory
	Metadata     OIDMetadata
	FriendlyName string
	IsConsistent bool
}
