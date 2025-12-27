package collector

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

// StateManager maneja la persistencia de estado por impresora
type StateManager struct {
	stateDir string
}

// NewStateManager crea un nuevo gestor de estado
func NewStateManager(stateDir string) *StateManager {
	// Crear directorio si no existe
	os.MkdirAll(stateDir, 0755)
	return &StateManager{stateDir: stateDir}
}

// LoadState carga el estado anterior de una impresora
func (sm *StateManager) LoadState(printerIP string) (*PrinterState, error) {
	filename := sm.getStateFilename(printerIP)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No existe estado anterior (primer poll)
		}
		return nil, err
	}

	var state PrinterState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

// SaveState guarda el estado actual de una impresora (se sobrescribe)
func (sm *StateManager) SaveState(printerIP string, counters CountersInfo) error {
	state := PrinterState{
		LastPollAt: time.Now().UTC(),
		Counters:   counters,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	filename := sm.getStateFilename(printerIP)
	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return err
	}

	return nil
}

// CalculateDelta calcula la diferencia entre estado actual y anterior
// Retorna nil si hay reset o no hay estado anterior
// También retorna un booleano indicando si se detectó un reset
func (sm *StateManager) CalculateDelta(printerIP string, currentCounters CountersInfo) (*CountersDiff, bool) {
	previousState, err := sm.LoadState(printerIP)
	if err != nil {
		return nil, false
	}

	// Si no hay estado anterior, no hay delta (primer poll)
	if previousState == nil {
		return nil, false
	}

	// Detectar resets: si actual < anterior, es un reset
	if currentCounters.TotalPages < previousState.Counters.TotalPages {
		return nil, true // delta = nil cuando hay reset, pero reset_detected = true
	}

	// Calcular delta
	delta := &CountersDiff{
		TotalPages: currentCounters.TotalPages - previousState.Counters.TotalPages,
		MonoPages:  currentCounters.MonoPages - previousState.Counters.MonoPages,
		ColorPages: currentCounters.ColorPages - previousState.Counters.ColorPages,
		ScanPages:  currentCounters.ScanPages - previousState.Counters.ScanPages,
		CopyPages:  currentCounters.CopyPages - previousState.Counters.CopyPages,
		FaxPages:   currentCounters.FaxPages - previousState.Counters.FaxPages,
	}

	return delta, false
}

// getStateFilename retorna la ruta del archivo de estado para una impresora
func (sm *StateManager) getStateFilename(printerIP string) string {
	// Sanitizar IP para usarla como filename (reemplazar puntos)
	sanitized := printerIP // puede mejorar si es necesario
	return filepath.Join(sm.stateDir, fmt.Sprintf("printer_%s.json", sanitized))
}
