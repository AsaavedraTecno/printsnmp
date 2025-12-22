package normalizer

// DataValue representa un valor con metadatos
type DataValue struct {
	Value      interface{} `json:"value,omitempty"`      // El valor real
	Unit       string      `json:"unit,omitempty"`       // Unidad: "pages", "percent", "raw", "unknown"
	Source     string      `json:"source,omitempty"`     // "standard_oid", "vendor_oid", "alt_oid"
	Confidence float64     `json:"confidence,omitempty"` // 0.0-1.0
	OID        string      `json:"oid,omitempty"`        // OID SNMP usado (ej: 1.3.6.1.2.1.43.10.2.1.4.1.1)
}

// StatusCode decodifica códigos de estado SNMP
type StatusCode struct {
	Code    int    `json:"code"`
	Meaning string `json:"meaning"` // "ready", "idle", "error", "offline"
	Details string `json:"details,omitempty"`
	OID     string `json:"oid,omitempty"` // OID SNMP usado
}

// NormalizedPrinter es la estructura mejorada con metadatos reales
type NormalizedPrinter struct {
	IP                string              `json:"ip"`
	Brand             string              `json:"brand"`
	BrandConfidence   float64             `json:"brandConfidence"`
	Identification    *IdentificationData `json:"identification"`
	Status            *StatusData         `json:"status"`
	Supplies          *SuppliesData       `json:"supplies"`
	Counters          *CountersData       `json:"counters"`
	UnsupportedFields []string            `json:"unsupportedFields"` // Campos no disponibles en este dispositivo
	RealErrors        []string            `json:"realErrors"`        // Errores reales (timeout, auth, etc)
	MissingSections   []string            `json:"missingSections"`   // Secciones sin datos
	Metadata          *Metadata           `json:"metadata"`
	Timestamp         string              `json:"timestamp"`
}

// Metadata contiene info de la recolección
type Metadata struct {
	ResponseTimeMs int64          `json:"responseTimeMs"`
	ProbeAttempts  int            `json:"probeAttempts"`
	ProbeStatus    string         `json:"probeStatus"` // "success", "slow", "partial", "failed"
	OIDsAttempted  int            `json:"oidsAttempted"`
	OIDsSuccessful int            `json:"oidsSuccessful"`
	TimeoutEncoded bool           `json:"timeoutEncoded"`        // Si hubo timeout
	PartialData    bool           `json:"partialData"`           // Si los datos están incompletos
	OIDCoverage    map[string]int `json:"oidCoverage,omitempty"` // Conteo por tipo de OID
}

// IdentificationData con metadatos
type IdentificationData struct {
	Model           *DataValue `json:"model,omitempty"`
	SerialNumber    *DataValue `json:"serialNumber,omitempty"`
	FirmwareVersion *DataValue `json:"firmwareVersion,omitempty"`
	Description     *DataValue `json:"description,omitempty"`
}

// StatusData con códigos decodificados
type StatusData struct {
	GeneralStatus *StatusCode `json:"generalStatus,omitempty"`
	OverallStatus *StatusCode `json:"overallStatus,omitempty"`
	DoorStatus    *StatusCode `json:"doorStatus,omitempty"`
	TonerStatus   *StatusCode `json:"tonerStatus,omitempty"`
}

// SupplyLevel mejorado
type SupplyLevel struct {
	Value      int     `json:"value"`            // Valor raw
	Unit       string  `json:"unit"`             // "percent", "pages", "raw"
	Confidence float64 `json:"confidence"`       // Confianza 0-1
	Status     string  `json:"status"`           // "ok", "warning", "critical"
	Source     string  `json:"source,omitempty"` // OID fuente
	OID        string  `json:"oid,omitempty"`    // OID SNMP específico
}

// SuppliesData normalizado
type SuppliesData struct {
	TonerBlack      *SupplyLevel            `json:"tonerBlack,omitempty"`
	TonerCyan       *SupplyLevel            `json:"tonerCyan,omitempty"`
	TonerMagenta    *SupplyLevel            `json:"tonerMagenta,omitempty"`
	TonerYellow     *SupplyLevel            `json:"tonerYellow,omitempty"`
	DrumUnit        *SupplyLevel            `json:"drumUnit,omitempty"`
	WasteContainer  *SupplyLevel            `json:"wasteContainer,omitempty"`
	DynamicSupplies map[string]*SupplyLevel `json:"dynamicSupplies,omitempty"` // Consumibles descubiertos via WALK
}

// CountersData mejorado
type CountersData struct {
	TotalPages     *DataValue `json:"totalPages,omitempty"`
	ColorPages     *DataValue `json:"colorPages,omitempty"`
	MonthlyPages   *DataValue `json:"monthlyPages,omitempty"`
	BWPagesPrinted *DataValue `json:"bwPagesPrinted,omitempty"`
	PagesBN        *DataValue `json:"pagesBN,omitempty"`    // B&W pages (vendor-specific)
	PagesColor     *DataValue `json:"pagesColor,omitempty"` // Color pages (vendor-specific)
}
