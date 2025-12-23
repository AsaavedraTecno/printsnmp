package oids

// Estructura para OIDs de consulta directa
type OIDConsulta struct {
	Nombre string
	OID    string
}

// ExtractOIDs extrae solo los OIDs de una lista de OIDConsulta
func ExtractOIDs(consultas []OIDConsulta) []string {
	result := make([]string, len(consultas))
	for i, c := range consultas {
		result[i] = c.OID
	}
	return result
}

// OIDs estándar RFC 3805 para impresoras
const (
	// Contadores de página - Formato base
	PageCountersBase = "1.3.6.1.2.1.43.10.2.1"

	// Identificación de dispositivo
	DeviceInfo  = "1.3.6.1.2.1.25.3.2.1"
	GeneralInfo = "1.3.6.1.2.1.1"
	Environment = "1.3.6.1.2.1.25.3.3.1"

	// Consumibles/Suministros
	ConsumablesBase  = "1.3.6.1.2.1.43.11.1.1"
	ConsumablesDesc  = "1.3.6.1.2.1.43.11.1.1.6.1"
	ConsumablesLevel = "1.3.6.1.2.1.43.11.1.1.9.1"
	ConsumablesMax   = "1.3.6.1.2.1.43.11.1.1.8.1"

	// Bandeja de entrada
	InputTrayBase  = "1.3.6.1.2.1.43.8.2.1.9.1"
	OutputTrayBase = "1.3.6.1.2.1.43.9.2.1.9.1"

	// OIDs de identificación comunes
	SysDescr        = "1.3.6.1.2.1.1.1.0"
	Hostname        = "1.3.6.1.2.1.1.5.0"
	Model           = "1.3.6.1.2.1.25.3.2.1.3.1"
	SerialNumber    = "1.3.6.1.2.1.43.5.1.1.17.1"
	FirmwareVersion = "1.3.6.1.2.1.25.3.3.1.1.1"

	// OIDs de estado
	GeneralStatus  = "1.3.6.1.2.1.25.3.2.1.5.1"
	DetailedStatus = "1.3.6.1.2.1.43.18.1.1.2.0"
	// OIDs de entrada/salida de bandejas
	InputTrayStatus  = "1.3.6.1.2.1.43.8.2.1.9.1.1"
	OutputTrayStatus = "1.3.6.1.2.1.43.9.2.1.9.1.1"
	InputTrayBase2   = "1.3.6.1.2.1.43.8.2.1"
	OutputTrayBase2  = "1.3.6.1.2.1.43.9.2.1"

	// OIDs de red
	IPAddress   = "1.3.6.1.2.1.4.20.1.1.0"
	MacAddress  = "1.3.6.1.2.1.2.2.1.6.1"
	Gateway     = "1.3.6.1.2.1.4.1.0"
	SubnetMask  = "1.3.6.1.2.1.4.20.1.3.0"
	DhcpEnabled = "1.3.6.1.2.1.25.3.2.1.5.1"

	// OIDs administrativos útiles
	SystemDescription = "1.3.6.1.2.1.1.4.0" // Contacto del administrador
	SystemLocation    = "1.3.6.1.2.1.1.6.0" // Ubicación de la impresora
	SystemUptime      = "1.3.6.1.2.1.1.3.0" // Tiempo de funcionamiento
	SystemServices    = "1.3.6.1.2.1.1.7.0" // Servicios disponibles

	// OIDs de ambiente/temperatura (para algunas impresoras)
	TemperatureValue  = "1.3.6.1.2.1.25.3.3.1.2"
	TemperatureStatus = "1.3.6.1.2.1.25.3.3.1.5"

	// OIDs para información de bandejas
	InputTrayCount  = "1.3.6.1.2.1.43.8.2.1.1"
	OutputTrayCount = "1.3.6.1.2.1.43.9.2.1.1"

	// OIDs de disponibilidad de papel/suministros
	PaperTrayStatus = "1.3.6.1.2.1.43.8.2.1.9"
	SupplyStatus    = "1.3.6.1.2.1.43.11.1.1.5"
)

// MapaContadoresEstándar mapea OIDs de contadores
// Formato con punto inicial (como aparecen en el SNMP desde WALK)
var MapaContadoresRFC3805 = map[string]string{
	// Contadores principales estándar
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.4.1.1": "Páginas Totales",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.4.1.2": "Páginas Monocromáticas",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.4.1.3": "Páginas a Color",

	// Contadores por función
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.2.1.1": "Página - Impresora",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.3.1.1": "Página - Fotocopiadora",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.5.1.1": "Página - Escáner",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.6.1.1": "Página - Fax",

	// Contadores adicionales Xerox
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.9.1.1":  "Páginas a Color",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.10.1.1": "Páginas Monocromáticas",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.11.1.1": "Páginas Duplex",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.12.1.1": "Páginas B&N Duplex",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.13.1.1": "Páginas Copia",
	"pageCounters__.1.3.6.1.2.1.43.10.2.1.14.1.1": "Páginas Copia Color",

	// Formato sin punto inicial (alternativa)
	"pageCounters__1.3.6.1.2.1.43.10.2.1.4.1.1":  "Páginas Totales",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.4.1.2":  "Páginas Monocromáticas",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.4.1.3":  "Páginas a Color",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.2.1.1":  "Página - Impresora",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.3.1.1":  "Página - Fotocopiadora",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.5.1.1":  "Página - Escáner",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.6.1.1":  "Página - Fax",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.9.1.1":  "Páginas a Color",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.10.1.1": "Páginas Monocromáticas",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.11.1.1": "Páginas Duplex",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.12.1.1": "Páginas B&N Duplex",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.13.1.1": "Páginas Copia",
	"pageCounters__1.3.6.1.2.1.43.10.2.1.14.1.1": "Páginas Copia Color",

	// Solo OID sin prefijo
	"1.3.6.1.2.1.43.10.2.1.4.1.1": "Páginas Totales",
	"1.3.6.1.2.1.43.10.2.1.4.1.2": "Páginas Monocromáticas",
	"1.3.6.1.2.1.43.10.2.1.4.1.3": "Páginas a Color",
}

// OIDsWalkFabricante define los OIDs base para descubrimiento por fabricante
var OIDsWalkFabricante = []struct {
	Prefijo string
	OID     string
}{
	{"hp", "1.3.6.1.4.1.11.2.3.9.4.2"},
	{"hp_alt", "1.3.6.1.4.1.11.2.3.9.4.3"},
	{"samsung", "1.3.6.1.4.1.236.11.5.1"},
	{"samsung_alt", "1.3.6.1.4.1.236.11.5.11"},
	{"xerox", "1.3.6.1.4.1.253.8.53.3"},
	{"xerox_alt", "1.3.6.1.4.1.253.8.53.4"},
	{"ricoh", "1.3.6.1.4.1.367.3.2"},
	{"konica", "1.3.6.1.4.1.1021.1.2"},
	{"canon", "1.3.6.1.4.1.3582.1.1"},
	{"kyocera", "1.3.6.1.4.1.2297.4.13"},
}

// OIDsDecubrimiento lista OIDs para búsqueda exhaustiva de datos adicionales
var OIDsDescubrimiento = []struct {
	Nombre string
	OID    string
}{
	{"consumibles", "1.3.6.1.2.1.43.11.1.1"},
	{"contadores", "1.3.6.1.2.1.43.10.2.1"},
	{"infoDispositivo", "1.3.6.1.2.1.25.3.2.1"},
	{"ambiente", "1.3.6.1.2.1.25.3.3.1"},
	{"infoGeneral", "1.3.6.1.2.1.1"},
	// Xerox
	{"xeroxContadores", "1.3.6.1.4.1.253.8.53.3.2.1"},
	{"xeroxSuministros", "1.3.6.1.4.1.253.8.53.13"},
	// HP
	{"hpContadores", "1.3.6.1.4.1.11.2.3.9.4.2.1.4"},
	{"hpSuministros", "1.3.6.1.4.1.11.2.3.9.4.3"},
	{"hpEstado", "1.3.6.1.4.1.11.2.3.9.4.2.1.5"},
	// Samsung
	{"samsungContadores", "1.3.6.1.4.1.236.11.5.1.1"},
	{"samsungSuministros", "1.3.6.1.4.1.236.11.5.11.1"},
	{"samsungEstado", "1.3.6.1.4.1.236.11.5.11.7"},
	// Kyocera
	{"kyoceraContadores", "1.3.6.1.4.1.2297.3"},
	// Ricoh
	{"ricohContadores", "1.3.6.1.4.1.367.3.2.1"},
}

// OIDsContadoresDirectos contiene consultas directas a OIDs de contadores para todos los fabricantes
var OIDsContadoresDirectos = []OIDConsulta{
	// Estándares RFC 3805
	{"totalPages", "1.3.6.1.2.1.43.10.2.1.4.1.1"},
	{"monochromedPages", "1.3.6.1.2.1.43.10.2.1.4.1.2"},
	{"colorPages", "1.3.6.1.2.1.43.10.2.1.4.1.3"},
	// Alternativas estándar
	{"totalPages", "1.3.6.1.2.1.43.10.2.1.4.1.0"},
	{"monochromedPages", "1.3.6.1.2.1.43.10.2.1.4.2.0"},
	{"colorPages", "1.3.6.1.2.1.43.10.2.1.4.3.0"},
	// HP LaserJet
	{"totalPagesHP", "1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.1"},
	{"colorPagesHP", "1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.3"},
	{"monoPagesHP", "1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2"},
	{"totalPagesHP2", "1.3.6.1.4.1.11.2.3.9.4.2.1.1.1.5"},
	{"colorCountHP", "1.3.6.1.4.1.11.2.3.9.4.2.1.1.1.6"},
	// Samsung
	{"totalPagesSamsung", "1.3.6.1.4.1.236.11.5.1.1.1.2.1.0"},
	{"colorPagesSamsung", "1.3.6.1.4.1.236.11.5.1.1.1.2.2.0"},
	{"monoPagesSamsung", "1.3.6.1.4.1.236.11.5.1.1.1.2.3.0"},
	// Xerox
	{"printedPages", "1.3.6.1.4.1.253.8.53.3.2.1.5.1.1.12"},
	{"copiedPages", "1.3.6.1.4.1.253.8.53.3.2.1.5.1.1.13"},
	{"scannedPages", "1.3.6.1.4.1.253.8.53.3.2.1.5.1.1.14"},
	{"colorXerox", "1.3.6.1.4.1.253.8.53.3.2.1.5.1.1.15"},
	{"monoXerox", "1.3.6.1.4.1.253.8.53.3.2.1.5.1.1.16"},
	// Ricoh
	{"totalPagesRicoh", "1.3.6.1.4.1.367.3.2.1.5.1.1.5.0"},
	{"colorRicoh", "1.3.6.1.4.1.367.3.2.1.5.1.1.6.0"},
	{"monoRicoh", "1.3.6.1.4.1.367.3.2.1.5.1.1.7.0"},
	// Konica Minolta
	{"totalPagesKonica", "1.3.6.1.4.1.1021.1.2.1.5.41.7.1.1"},
	{"colorKonica", "1.3.6.1.4.1.1021.1.2.1.5.41.7.1.2"},
	// Canon
	{"totalPagesCanon", "1.3.6.1.4.1.3582.1.1.1.1.1.5.0"},
	{"colorCanon", "1.3.6.1.4.1.3582.1.1.1.1.1.6.0"},
	// Kyocera
	{"totalPagesKyocera", "1.3.6.1.4.1.2297.4.13.1.1.1.1.0"},
	{"colorKyocera", "1.3.6.1.4.1.2297.4.13.1.1.1.2.0"},
}
