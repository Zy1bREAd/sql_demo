package utils

import (
	"fmt"
	"io"
	"log"
	"os"
)

const (
	LogLevelError = 0
	LogLevelWarn  = 1
	LogLevelInfo  = 2
	LogLevelDebug = 3
)

var levelMap = map[int]string{
	LogLevelError: "ERROR",
	LogLevelWarn:  "WARN",
	LogLevelInfo:  "INFO",
	LogLevelDebug: "DEBUG",
}

func generateLog(level int, errorTitle string, msg string) string {
	levelStr, ok := levelMap[level]
	if !ok {
		return "log level is not found"
	}
	formatMsg := fmt.Sprintf("[%s] <%s> %s", levelStr, errorTitle, msg)
	return formatMsg
}

// 生成自定义错误
func GenerateError(errorTitle string, msg string) error {
	DebugPrint(errorTitle, msg)
	newErr := fmt.Errorf("[%s] %s", errorTitle, msg)
	return newErr
}

// 调试打印信息
func DebugPrint(title string, msg any) {
	if assertVal, ok := msg.(string); ok {
		log.Println(generateLog(LogLevelDebug, title, assertVal))
		return
	} else if assertVal, ok := msg.(int); ok {
		log.Println(generateLog(LogLevelDebug, title, string(rune(assertVal))))
		return
	} else if assertVal, ok := msg.(error); ok {
		log.Println(generateLog(LogLevelDebug, title, assertVal.Error()))
		return
	}
	log.Println(msg)
}

// 打印错误信息
func ErrorPrint(title string, msg any) {
	if assertVal, ok := msg.(string); ok {
		log.Println(generateLog(LogLevelError, title, assertVal))
		return
	} else if assertVal, ok := msg.(int); ok {
		log.Println(generateLog(LogLevelError, title, string(rune(assertVal))))
		return
	} else if assertVal, ok := msg.(error); ok {
		log.Println(generateLog(LogLevelError, title, assertVal.Error()))
		return
	}
	log.Println(msg)
}

// 日志文件记录
func StartFileLogging() *os.File {
	filePath := "logs"
	fileName := "sql_demo.log"
	// 检查是否有路径
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.Mkdir(filePath, 0644)
			if err != nil {
				log.Println(err)
				panic(err)
			}
		} else {
			log.Println(err)
			panic(err)
		}
	}

	logFile, err := os.OpenFile(filePath+"/"+fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
		panic(err)
	}
	// 同时写入日志文件和屏幕
	multiWriter := io.MultiWriter(logFile, os.Stdout)
	log.SetOutput(multiWriter)
	return logFile
}
