package util

import (
	"bytes"
	"io"
	"log"
	"sync"
)

var logLog = NewLogger("[LOG] ", LogLevelEnabled)

type LogLevel byte

const (
	LogLevelUnsafe  LogLevel = 0
	LogLevelTrace   LogLevel = 1
	LogLevelDebug   LogLevel = 2
	LogLevelEnabled LogLevel = 3
)

// maxBufferedLog bounds how much output a level keeps while it has no
// destination yet. Trace output is produced for every USB packet, so an
// unbounded buffer grows for as long as the process runs.
const maxBufferedLog = 256 * 1024

// logBuffer holds log output until a destination is configured and then
// forwards to it. Every logger of one level shares a logBuffer, so it must be
// safe for concurrent use.
type logBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	output io.Writer
}

func newLogBuffer() *logBuffer {
	return &logBuffer{}
}

func (logBuf *logBuffer) Write(p []byte) (n int, err error) {
	logBuf.mu.Lock()
	output := logBuf.output
	if output == nil {
		if logBuf.buffer.Len()+len(p) <= maxBufferedLog {
			logBuf.buffer.Write(p)
		}
		logBuf.mu.Unlock()
		return len(p), nil
	}
	logBuf.mu.Unlock()
	return output.Write(p)
}

func (logBuf *logBuffer) setOutput(output io.Writer) {
	logBuf.mu.Lock()
	defer logBuf.mu.Unlock()
	if logBuf.buffer.Len() > 0 {
		output.Write(logBuf.buffer.Bytes())
		logBuf.buffer.Reset()
	}
	logBuf.output = output
}

var enabledLogOutput *logBuffer = newLogBuffer()
var debugLogOutput *logBuffer = newLogBuffer()
var traceLogOutput *logBuffer = newLogBuffer()
var unsafeLogOutput *logBuffer = newLogBuffer()

func SetLogOutput(out io.Writer) {
	enabledLogOutput.setOutput(out)
}

// SetLogLevel routes every level at or above level to the log output and
// discards the rest.
func SetLogLevel(level LogLevel) {
	route := func(buf *logBuffer, bufLevel LogLevel, next io.Writer) {
		if level <= bufLevel {
			buf.setOutput(next)
		} else {
			buf.setOutput(io.Discard)
		}
	}
	route(unsafeLogOutput, LogLevelUnsafe, traceLogOutput)
	route(traceLogOutput, LogLevelTrace, debugLogOutput)
	route(debugLogOutput, LogLevelDebug, enabledLogOutput)
	logLog.Printf("Log Level Set: %d\n", level)
}

func NewLogger(prefix string, level LogLevel) *log.Logger {
	if level == LogLevelEnabled {
		return log.New(enabledLogOutput, prefix, 0)
	} else if level == LogLevelDebug {
		return log.New(debugLogOutput, prefix, 0)
	} else if level == LogLevelTrace {
		return log.New(traceLogOutput, prefix, 0)
	} else {
		return log.New(unsafeLogOutput, prefix, 0)
	}
}
