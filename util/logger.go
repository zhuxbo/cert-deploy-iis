package util

import (
	"log"
	"os"
)

var (
	DebugMode = false
	debugLog  = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)
	infoLog   = log.New(os.Stdout, "[INFO] ", log.LstdFlags)
	warnLog   = log.New(os.Stdout, "[WARN] ", log.LstdFlags)
	errorLog  = log.New(os.Stderr, "[ERROR] ", log.LstdFlags)
)

func Debug(format string, v ...interface{}) {
	if DebugMode {
		debugLog.Printf(format, v...)
	}
}

func Info(format string, v ...interface{}) {
	infoLog.Printf(format, v...)
}

func Warn(format string, v ...interface{}) {
	warnLog.Printf(format, v...)
}

func Error(format string, v ...interface{}) {
	errorLog.Printf(format, v...)
}
