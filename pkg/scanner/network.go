package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseIPRange parsea un rango de IPs en formato "192.168.1.1-254"
// Retorna lista de IPs individuales
func ParseIPRange(ipRange string) ([]string, error) {
	parts := strings.Split(ipRange, "-")
	if len(parts) == 2 {
		// Formato: 192.168.1.1-254
		return parseRangeFormat(parts[0], parts[1])
	}

	if len(parts) == 1 {
		// IP individual
		if net.ParseIP(ipRange) != nil {
			return []string{ipRange}, nil
		}
		return nil, fmt.Errorf("formato de IP inválido: %s", ipRange)
	}

	return nil, fmt.Errorf("formato de rango inválido: %s. Use: 192.168.1.1-254 o 192.168.1.0/24", ipRange)
}

// parseRangeFormat maneja rangos como "192.168.1.1" y "254"
func parseRangeFormat(startIP, endOctet string) ([]string, error) {
	// Parsear IP inicial
	ip := net.ParseIP(startIP)
	if ip == nil {
		return nil, fmt.Errorf("IP inicial inválida: %s", startIP)
	}

	// Si startIP es una IPv4
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("solo se soporta IPv4: %s", startIP)
	}

	// Parsear octeto final
	endNum, err := strconv.Atoi(endOctet)
	if err != nil {
		return nil, fmt.Errorf("octeto final inválido: %s", endOctet)
	}

	if endNum < 0 || endNum > 255 {
		return nil, fmt.Errorf("octeto fuera de rango (0-255): %d", endNum)
	}

	// Generar rango de IPs
	startNum := int(ipv4[3])
	var ips []string

	// Rango normal (ascendente)
	for i := startNum; i <= endNum; i++ {
		ips = append(ips, net.IPv4(ipv4[0], ipv4[1], ipv4[2], byte(i)).String())
	}

	return ips, nil
}
