package collector

import (
	"sync"
	"time"
)

// RateLimiter controla la velocidad de ejecución de operaciones
type RateLimiter struct {
	maxConcurrent int
	semaphore     chan struct{}
	mu            sync.Mutex
}

// NewRateLimiter crea un nuevo rate limiter
func NewRateLimiter(maxConcurrent int) *RateLimiter {
	return &RateLimiter{
		maxConcurrent: maxConcurrent,
		semaphore:     make(chan struct{}, maxConcurrent),
	}
}

// Acquire intenta adquirir un slot
func (rl *RateLimiter) Acquire() {
	rl.semaphore <- struct{}{}
}

// Release libera un slot
func (rl *RateLimiter) Release() {
	<-rl.semaphore
}

// Wait espera a que haya un slot disponible
func (rl *RateLimiter) Wait() {
	rl.Acquire()
}

// Delay proporciona un delay mínimo entre operaciones
type Delay struct {
	minDelay time.Duration
	lastTime time.Time
	mu       sync.Mutex
}

// NewDelay crea un nuevo delay controlador
func NewDelay(minDelay time.Duration) *Delay {
	return &Delay{
		minDelay: minDelay,
		lastTime: time.Now().Add(-minDelay), // Permitir la primera operación inmediatamente
	}
}

// Wait espera el tiempo necesario
func (d *Delay) Wait() {
	d.mu.Lock()
	defer d.mu.Unlock()

	elapsed := time.Since(d.lastTime)
	if elapsed < d.minDelay {
		time.Sleep(d.minDelay - elapsed)
	}

	d.lastTime = time.Now()
}
