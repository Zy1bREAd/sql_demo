package apis

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

var levelMap = map[int]string{
	0: "ERROR",
	1: "WARN",
	2: "INFO",
	3: "DEBUG",
}

func ErrorRecover() {
	if err := recover(); err != nil {
		now := time.Now()
		log.Printf("[%s][ERRRO] - %s", now.Format("2006-01-02T15:04:05"), err)
		// 打印goroutine堆栈信息
		// buf := make([]byte, 1024)
		// for {
		// 	n := runtime.Stack(buf, false)
		// 	if n < len(buf) {
		// 		buf = buf[:n]
		// 		runtime.Breakpoint()
		// 	}
		// 	buf = make([]byte, 2*len(buf))
		// }
		panic(err)
	}
}

func generateLog(level int, errorTitle string, msg string) string {
	levelStr, ok := levelMap[level]
	if !ok {
		return "log level is not found"
	}
	formatMsg := fmt.Sprintf("[%s] <%s> %s", levelStr, errorTitle, msg)
	log.Println(formatMsg)
	return formatMsg
}

func GenerateError(errorTitle string, msg string) error {
	newErr := errors.New(generateLog(0, errorTitle, msg))
	return newErr
}

func DebugPrint(title string, msg any) {
	if assertVal, ok := msg.(string); ok {
		log.Println(generateLog(3, title, assertVal))
		return
	} else if assertVal, ok := msg.(int); ok {
		log.Println(generateLog(3, title, string(rune(assertVal))))
		return
	}
	log.Println(msg)
}

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

	log.SetOutput(logFile)
	return logFile
}
