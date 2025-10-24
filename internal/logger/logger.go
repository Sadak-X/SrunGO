// 写日志的相关操作
package logger

import (
	"fmt"
	"os"
	"time"
)

// 日志等级
const (
	DEBUG = "DEBUG"
	INFO  = "INFO"
	WARN  = "WARN"
	ERROR = "ERROR"
)

type Logger struct {
	LogFile   string
	DebugMode bool
}

// 创造一个写入实例
func New(logFile string, debugMode bool) *Logger {
	return &Logger{
		LogFile:   logFile,
		DebugMode: debugMode,
	}
}

// 写日志文件写入日志，可选是否显示在控制台
func (l *Logger) Log(message string, level string, showConsole bool) {
	timestamp := time.Now().Format(time.RFC3339)
	logLine := fmt.Sprintf("%s [%s] %s\n", timestamp, level, message)

	logFile, err := os.OpenFile(l.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		logFile.WriteString(logLine)
		logFile.Close()
	} else {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to write log file: %v\n", err)
	}

	if showConsole || level == ERROR || (l.DebugMode && level == DEBUG) {
		if level == ERROR {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", level, message)
		} else {
			fmt.Printf("[%s] %s\n", level, message)
		}
	}
}

// 根据配置文件中的 debug mode 决定是否产生这些日志内容
func (l *Logger) Debug(message string, showConsole bool) {
	if l.DebugMode {
		l.Log(message, DEBUG, showConsole)
	}
}

func (l *Logger) Info(message string, showConsole bool) {
	l.Log(message, INFO, showConsole)
}

func (l *Logger) Warn(message string, showConsole bool) {
	l.Log(message, WARN, showConsole)
}

func (l *Logger) Error(message string, showConsole bool) {
	l.Log(message, ERROR, showConsole)
}
