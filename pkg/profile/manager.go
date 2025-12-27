package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/asaavedra/agent-snmp/pkg/snmp"
)

// Manager maneja la persistencia y carga de perfiles
type Manager struct {
	profileDir string
	cache      map[string]*Profile
	mu         sync.RWMutex
}

// NewManager crea un nuevo ProfileManager
func NewManager(profileDir string) (*Manager, error) {
	// Crear directorio si no existe
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return nil, fmt.Errorf("error creando directorio de perfiles: %w", err)
	}

	return &Manager{
		profileDir: profileDir,
		cache:      make(map[string]*Profile),
	}, nil
}

// GetOrDiscover carga un perfil existente o retorna nil para discovery
func (m *Manager) GetOrDiscover(printerID string) *Profile {
	m.mu.RLock()

	// Primero verificar cache en memoria
	if p, exists := m.cache[printerID]; exists {
		defer m.mu.RUnlock()
		return p
	}
	m.mu.RUnlock()

	// Luego verificar en disco
	p, err := m.loadFromDisk(printerID)
	if err == nil && p != nil {
		// Cachear en memoria (con lock de escritura)
		m.mu.Lock()
		m.cache[printerID] = p
		m.mu.Unlock()
		return p
	}

	// No existe: necesita discovery
	return nil
}

// SaveProfile guarda un perfil después del discovery
func (m *Manager) SaveProfile(profile *Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if profile == nil || profile.PrinterID == "" {
		return fmt.Errorf("profile inválido para guardar")
	}

	// Guardar en memoria
	m.cache[profile.PrinterID] = profile

	// Guardar en disco
	return m.saveToDisk(profile)
}

// DiscoverAndSave ejecuta discovery de un nuevo dispositivo y guarda el perfil
func (m *Manager) DiscoverAndSave(client *snmp.SNMPClient, ip, brand, model, serialNumber string) (*Profile, error) {
	// Ejecutar discovery
	discoverer := NewDiscoverer(client)
	profile, err := discoverer.DiscoverProfile(ip, brand, model, serialNumber)
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	// Guardar el perfil
	if err := m.SaveProfile(profile); err != nil {
		return profile, fmt.Errorf("failed to save profile: %w", err)
	}

	return profile, nil
}

// TODO: Implementar validación persistente cuando sea necesario
// UpdateValidation actualiza validez del perfil después de polling
func (m *Manager) UpdateValidation(printerID string, success bool, err string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, exists := m.cache[printerID]
	if !exists {
		return fmt.Errorf("profile no encontrado: %s", printerID)
	}

	p.LastValidatedAt = time.Now()
	p.DiscoveryAttempts++

	if success {
		p.ErrorCount = 0
		p.LastError = ""
		p.SuccessRate = 0.95 // Asumimos ~95% si fue exitoso
	} else {
		p.ErrorCount++
		p.LastError = err
		// Reducir success rate si hay errores
		if p.DiscoveryAttempts > 0 {
			p.SuccessRate = float64(p.DiscoveryAttempts-p.ErrorCount) / float64(p.DiscoveryAttempts)
		}
	}

	// Guardar cambios en disco
	return m.saveToDisk(p)
}

// TODO: Implementar redescubrimiento automático cuando sea necesario
// NeedsRediscovery verifica si el perfil necesita ser redescubierto
func (m *Manager) NeedsRediscovery(printerID string) bool {
	p := m.GetOrDiscover(printerID)
	if p == nil {
		return true // No existe, necesita discovery inicial
	}

	// Redescubrir si:
	// 1. Hace más de 7 días que se descubrió
	// 2. Success rate cayó por debajo del 80%
	// 3. Hay más de 5 errores consecutivos

	if time.Since(p.DiscoveredAt) > 7*24*time.Hour {
		return true
	}

	if p.SuccessRate < 0.8 {
		return true
	}

	if p.ErrorCount > 5 {
		return true
	}

	return false
}

// TODO: Implementar carga en caché cuando sea necesario para optimizar startup
// LoadAll carga todos los perfiles en memoria
func (m *Manager) LoadAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(m.profileDir)
	if err != nil {
		return fmt.Errorf("error leyendo directorio de perfiles: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(m.profileDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Warning: error leyendo perfil %s: %v\n", entry.Name(), err)
			continue
		}

		var p Profile
		if err := json.Unmarshal(data, &p); err != nil {
			fmt.Printf("Warning: error parseando perfil %s: %v\n", entry.Name(), err)
			continue
		}

		m.cache[p.PrinterID] = &p
	}

	return nil
}

// --- Métodos privados ---

func (m *Manager) loadFromDisk(printerID string) (*Profile, error) {
	// Buscar archivo con nombre basado en printerID
	filePath := filepath.Join(m.profileDir, m.getFileName(printerID))

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("error parseando perfil: %w", err)
	}

	return &p, nil
}

func (m *Manager) saveToDisk(p *Profile) error {
	filePath := filepath.Join(m.profileDir, m.getFileName(p.PrinterID))

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializando perfil: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("error escribiendo perfil: %w", err)
	}

	return nil
}

func (m *Manager) getFileName(printerID string) string {
	// Reemplazar caracteres especiales para nombre de archivo seguro
	safeID := printerID
	for _, ch := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"} {
		safeID = strings.ReplaceAll(safeID, ch, "_")
	}
	return safeID + ".json"
}
