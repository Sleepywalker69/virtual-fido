package desktop

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// LogRing keeps the most recent log lines for display. It is an io.Writer, so
// it can receive the authenticator's log output.
type LogRing struct {
	mu      sync.Mutex
	max     int
	lines   []string
	partial string
	version uint64
	tee     io.Writer
}

// SetTee copies everything written from now on to w as well (nil to stop).
func (r *LogRing) SetTee(w io.Writer) {
	r.mu.Lock()
	r.tee = w
	r.mu.Unlock()
}

func NewLogRing(maxLines int) *LogRing {
	return &LogRing{max: maxLines}
}

func (r *LogRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tee != nil {
		r.tee.Write(p)
	}
	text := r.partial + string(p)
	parts := strings.Split(text, "\n")
	r.partial = parts[len(parts)-1]
	stamp := time.Now().Format("15:04:05 ")
	for _, line := range parts[:len(parts)-1] {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		r.lines = append(r.lines, stamp+line)
	}
	if over := len(r.lines) - r.max; over > 0 {
		r.lines = append([]string(nil), r.lines[over:]...)
	}
	r.version++
	return len(p), nil
}

// Printf adds an app message to the log.
func (r *LogRing) Printf(format string, args ...interface{}) {
	r.Write([]byte(fmt.Sprintf(format, args...) + "\n"))
}

// Snapshot returns the current lines and a version that changes whenever
// lines are added.
func (r *LogRing) Snapshot() ([]string, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...), r.version
}

// Version changes whenever lines are added.
func (r *LogRing) Version() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.version
}
