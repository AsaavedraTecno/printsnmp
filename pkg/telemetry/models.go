package telemetry

import (
	"time"

	"github.com/asaavedra/agent-snmp/pkg/collector"
)

// Telemetry es el payload atómico que representa el estado de UNA impresora
// en un momento específico, junto con métricas de cómo se obtuvo ese snapshot
type Telemetry struct {
	SchemaVersion string      `json:"schema_version"`
	EventID       string      `json:"event_id"`
	CollectedAt   time.Time   `json:"collected_at"`
	Source        AgentSource `json:"source"`
	Printer       PrinterInfo `json:"printer"`

	Counters *collector.CountersSnapshot `json:"counters,omitempty"`
	Supplies []SupplyInfo                `json:"supplies,omitempty"` // nil → null en JSON
	Alerts   []AlertInfo                 `json:"alerts,omitempty"`   // nil → null en JSON

	Metrics *MetricsInfo `json:"metrics,omitempty"`
}

// AgentSource describe quién envía el telemetry
type AgentSource struct {
	AgentID  string `json:"agent_id"` // "AGT-CL-001" (asignado por backend)
	Hostname string `json:"hostname"` // "srv-print-01" (detectado del SO)
	OS       string `json:"os"`       // "windows", "linux", "darwin"
	Version  string `json:"version"`  // "1.0.0" (versión del agente)
}

// PrinterInfo es la identidad del dispositivo (nunca cambia)
type PrinterInfo struct {
	ID              string  `json:"id"`               // "SEC30CDA7C72268-ZDBQBJCH500055B"
	IP              string  `json:"ip"`               // "192.168.150.35"
	Brand           string  `json:"brand"`            // "Samsung"
	BrandConfidence float64 `json:"brand_confidence"` // 0.96
	Model           *string `json:"model"`            // "Samsung M332x 382x 402x Series" (nil → null en JSON)
	SerialNumber    *string `json:"serial_number"`    // "ZDBQBJCH500055B" (nil → null en JSON)
	Hostname        *string `json:"hostname"`         // "SEC30CDA7C72268" (nil → null en JSON)
	MacAddress      *string `json:"mac_address"`      // "30:cd:a7:c7:22:68" (nil → null en JSON)
}

// StatusInfo es el estado actual del dispositivo
type StatusInfo struct {
	State               string `json:"state"`                     // "idle", "printing", "error", etc
	PageCount           int64  `json:"page_count"`                // 14372 (total acumulativo)
	SystemUptime        string `json:"system_uptime"`             // "41 días, 17 horas, 30 min" (legible para UI)
	SystemUptimeSeconds int64  `json:"system_uptime_seconds"`     // 3601847 (numérico para cálculos)
	SystemLocation      string `json:"system_location,omitempty"` // "Oficina Prevención de riesgos" (opcional)
}

// Nota: CountersInfo, CountersDiff y CountersSnapshot se definen en pkg/collector/data.go
// para evitar imports circulares. Se importan desde allá.
// CountersSnapshot se refiere en el JSON de queue/ como:
// {
//   "absolute": {...},
//   "delta": {...},
//   "reset_detected": bool
// }

// SupplyInfo describe UN consumible (tóner, drum, fuser, etc)
type SupplyInfo struct {
	ID         string `json:"id"`         // "toner_black", "drum_1", "fuser"
	Name       string `json:"name"`       // "Black Toner Cartridge"
	Type       string `json:"type"`       // "toner", "drum", "fuser", "waste", "roller"
	Level      int64  `json:"level"`      // 13950 (unidades crudas)
	MaxLevel   int64  `json:"max_level"`  // 15000
	Percentage int    `json:"percentage"` // 93
	Status     string `json:"status"`     // "ok", "low", "critical", "empty"
	// Nuevos campos para información detallada
	Model         string `json:"model,omitempty"`          // "CRUM-24030716547" - modelo/número de pieza
	SerialNumber  string `json:"serial_number,omitempty"`  // "3N6DG5XNMK"
	Brand         string `json:"brand,omitempty"`          // "Samsung", "Canon", "Fujifilm"
	OEM           string `json:"oem,omitempty"`            // OEM info si está disponible
	Description   string `json:"description,omitempty"`    // Descripción completa del SNMP
	ComponentType string `json:"component_type,omitempty"` // "imaging_unit", "transfer_roller", "fuser_film"
	PageCapacity  int64  `json:"page_capacity,omitempty"`  // Capacidad en páginas
	PartNumber    string `json:"part_number,omitempty"`    // Número de parte alternativo
}

// AlertInfo describe UNA alerta activa en el dispositivo
type AlertInfo struct {
	ID         string    `json:"id"`          // "alert_toner_low_magenta"
	Type       string    `json:"type"`        // "supply", "hardware", "network", "unknown"
	Severity   string    `json:"severity"`    // "info", "warning", "critical"
	Message    string    `json:"message"`     // "Magenta toner is low (20%)"
	DetectedAt time.Time `json:"detected_at"` // 2025-12-23T15:40:00Z
}

// CapabilitiesInfo describe las capacidades del dispositivo
type CapabilitiesInfo struct {
	SNMPVersion     string   `json:"snmp_version"`      // "2c", "1", "3"
	Duplex          bool     `json:"duplex"`            // true
	Color           bool     `json:"color"`             // true
	Scanner         bool     `json:"scanner"`           // true
	Fax             bool     `json:"fax"`               // false
	OidsSupported   []string `json:"oids_supported"`    // ["1.3.6.1.2.1.1.1.0", ...]
	OidsSuccessRate float64  `json:"oids_success_rate"` // 0.95
}

// MetricsInfo agrupa las métricas del poll SNMP
type MetricsInfo struct {
	Polling *PollingMetrics `json:"polling,omitempty"`
}

// PollingMetrics describe cómo fue obtener el snapshot
type PollingMetrics struct {
	ResponseTimeMs int       `json:"response_time_ms"` // 1693 (tiempo de respuesta SNMP)
	PollDurationMs int       `json:"poll_duration_ms"` // 2500 (duración total del poll)
	OidSuccessRate float64   `json:"oid_success_rate"` // 0.95 (qué porcentaje de OIDs respondieron)
	RetryCount     int       `json:"retry_count"`      // 0 (cuántos reintentos fue necesario)
	LastPollAt     time.Time `json:"last_poll_at"`     // 2025-12-23T15:47:10Z
	NextPollAt     time.Time `json:"next_poll_at"`     // 2025-12-23T16:47:20Z
	ErrorCount     int       `json:"error_count"`      // 0 (errores durante el poll)
}
