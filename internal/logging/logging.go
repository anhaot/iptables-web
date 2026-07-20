package logging

import (
	"log"
	"strings"
	"sync/atomic"
)

const (
	levelDebug int32 = iota
	levelInfo
	levelWarn
	levelError
	levelOff
)

var currentLevel atomic.Int32

func init() {
	currentLevel.Store(levelInfo)
}

func SetLevel(value string) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		currentLevel.Store(levelDebug)
	case "warn", "warning":
		currentLevel.Store(levelWarn)
	case "error":
		currentLevel.Store(levelError)
	case "off", "none":
		currentLevel.Store(levelOff)
	default:
		currentLevel.Store(levelInfo)
	}
}

func Debugf(format string, args ...interface{}) {
	output(levelDebug, "DEBUG: "+format, args...)
}

func Infof(format string, args ...interface{}) {
	output(levelInfo, format, args...)
}

func Warnf(format string, args ...interface{}) {
	output(levelWarn, "WARN: "+format, args...)
}

func Errorf(format string, args ...interface{}) {
	output(levelError, "ERROR: "+format, args...)
}

func output(level int32, format string, args ...interface{}) {
	if level < currentLevel.Load() {
		return
	}
	log.Printf(format, args...)
}
