package snmp

import (
	"fmt"
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
		return v
	case []byte:
		return string(v)
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
