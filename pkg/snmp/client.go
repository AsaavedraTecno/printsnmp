package snmp

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// SNMPClient wrapper alrededor de gosnmp para manejar SNMP v1/v2c
type SNMPClient struct {
	host      string
	port      uint16
	community string
	version   string
	timeout   time.Duration
	retries   int
}

// NewSNMPClient crea un nuevo cliente SNMP
func NewSNMPClient(host string, port uint16, community, version string, timeout time.Duration, retries int) *SNMPClient {
	return &SNMPClient{
		host:      host,
		port:      port,
		community: community,
		version:   version,
		timeout:   timeout,
		retries:   retries,
	}
}

// Get obtiene un único valor OID
func (sc *SNMPClient) Get(oid string, ctx *Context) (interface{}, error) {
	client, err := sc.connect()
	if err != nil {
		return nil, err
	}
	defer client.Conn.Close()

	result, err := client.Get([]string{oid})
	if err != nil {
		return nil, fmt.Errorf("error SNMP GET: %w", err)
	}

	if result == nil || len(result.Variables) == 0 {
		return nil, fmt.Errorf("sin respuesta para OID: %s", oid)
	}

	variable := result.Variables[0]

	// Verificar si hay error en la respuesta
	if result.Error != gosnmp.NoError {
		return nil, fmt.Errorf("SNMP error %d: %s", result.Error, result.Error.String())
	}

	// Convertir valor a string
	return parseValue(variable), nil
}

// GetMultiple obtiene múltiples OIDs
func (sc *SNMPClient) GetMultiple(oids []string, ctx *Context) (map[string]interface{}, error) {
	if len(oids) == 0 {
		return make(map[string]interface{}), nil
	}

	client, err := sc.connect()
	if err != nil {
		return nil, err
	}
	defer client.Conn.Close()

	result, err := client.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("error SNMP GET múltiple: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("sin respuesta para OIDs")
	}

	values := make(map[string]interface{})

	for i, variable := range result.Variables {
		if i < len(oids) {
			values[oids[i]] = parseValue(variable)
		}
	}

	return values, nil
}

// WalkResult contiene resultado de un SNMP WALK
type WalkResult struct {
	OID   string
	Value string
}

// Walk realiza SNMP WALK de un OID base
func (sc *SNMPClient) Walk(baseOID string, ctx *Context) ([]WalkResult, error) {
	client, err := sc.connect()
	if err != nil {
		return nil, err
	}
	defer client.Conn.Close()

	var results []WalkResult

	// gosnmp.WalkFunc es callback para cada OID encontrado
	err = client.Walk(baseOID, func(dataUnit gosnmp.SnmpPDU) error {
		results = append(results, WalkResult{
			OID:   dataUnit.Name,
			Value: parseValue(dataUnit),
		})
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error en SNMP WALK %s: %w", baseOID, err)
	}

	return results, nil
}

// WalkMultiple realiza SNMP WALK de múltiples OIDs base
func (sc *SNMPClient) WalkMultiple(baseOIDs []string, ctx *Context) (map[string][]WalkResult, error) {
	results := make(map[string][]WalkResult)

	for _, oid := range baseOIDs {
		walkResults, err := sc.Walk(oid, ctx)
		if err != nil {
			// Continuar con otros OIDs si uno falla
			results[oid] = []WalkResult{}
			continue
		}
		results[oid] = walkResults
	}

	return results, nil
}

// connect establece conexión SNMP
func (sc *SNMPClient) connect() (*gosnmp.GoSNMP, error) {
	var version gosnmp.SnmpVersion

	switch sc.version {
	case "1":
		version = gosnmp.Version1
	case "2c":
		version = gosnmp.Version2c
	default:
		version = gosnmp.Version2c
	}

	params := &gosnmp.GoSNMP{
		Target:    sc.host,
		Port:      sc.port,
		Community: sc.community,
		Version:   version,
		Timeout:   sc.timeout,
		Retries:   sc.retries,
	}

	err := params.Connect()
	if err != nil {
		return nil, fmt.Errorf("error conectando a %s:%d: %w", sc.host, sc.port, err)
	}

	return params, nil
}

// parseValue convierte un PDU variable a string
func parseValue(variable gosnmp.SnmpPDU) string {
	if variable.Value == nil {
		return ""
	}

	switch v := variable.Value.(type) {
	case string:
		// Limpiar null terminators
		return strings.TrimRight(v, "\x00")
	case []byte:
		// Si es exactamente 6 bytes, asumir que es MAC address en formato binario
		if len(v) == 6 {
			hexStr := hex.EncodeToString(v)
			return fmt.Sprintf("%s:%s:%s:%s:%s:%s", hexStr[0:2], hexStr[2:4], hexStr[4:6], hexStr[6:8], hexStr[8:10], hexStr[10:12])
		}

		// Para otros bytes, intentar interpretar como UTF-8
		if isValidUTF8(v) && isLikelyText(v) {
			str := string(v)
			// Limpiar null terminators
			return strings.TrimRight(str, "\x00")
		}

		// Si no es UTF-8 válido o no parece texto, retornar vacío
		return ""
	case int:
		return fmt.Sprintf("%d", v)
	case uint:
		return fmt.Sprintf("%d", v)
	case uint32:
		return fmt.Sprintf("%d", v)
	case uint64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// isValidUTF8 valida si un slice de bytes es UTF-8 válido
func isValidUTF8(b []byte) bool {
	for i := 0; i < len(b); {
		if b[i] < 0x80 {
			i++
		} else if b[i] < 0xC0 {
			return false
		} else if b[i] < 0xE0 {
			if i+1 >= len(b) {
				return false
			}
			i += 2
		} else if b[i] < 0xF0 {
			if i+2 >= len(b) {
				return false
			}
			i += 3
		} else if b[i] < 0xF8 {
			if i+3 >= len(b) {
				return false
			}
			i += 4
		} else {
			return false
		}
	}
	return true
}

// isLikelyText verifica si bytes parecen ser texto (no caracteres de control raros)
func isLikelyText(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	// Contar cuántos bytes son caracteres imprimibles o espacios en blanco
	printableCount := 0
	for _, c := range b {
		// ASCII printable: 32-126, más tab/newline/carriage return
		if (c >= 32 && c <= 126) || c == 9 || c == 10 || c == 13 {
			printableCount++
		}
	}

	// Si al menos el 80% de los bytes son imprimibles, parece texto
	return float64(printableCount)/float64(len(b)) >= 0.8
}

// ValidateConnection valida si es posible conectar
func (sc *SNMPClient) ValidateConnection() error {
	client, err := sc.connect()
	if err != nil {
		return err
	}
	defer client.Conn.Close()
	return nil
}

// Context contiene información de contexto para operaciones SNMP
type Context struct {
	Timeout time.Duration
	Retries int
	// Otros campos según sea necesario
}

// NewContext crea un nuevo contexto
func NewContext() *Context {
	return &Context{
		Timeout: 2 * time.Second,
		Retries: 1,
	}
}
