package apis

import (
	"errors"
	"fmt"
	"log"
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

func generateLog(level int, errorTitle string, msg string) error {
	levelStr, ok := levelMap[level]
	if !ok {
		return errors.New("log level is not found")
	}
	formatErrorMsg := fmt.Sprintf("[%s] <%s> %s", levelStr, errorTitle, msg)
	log.Println(formatErrorMsg)
	return errors.New(formatErrorMsg)
}

func GenerateError(errorTitle string, msg string) error {
	return generateLog(0, errorTitle, msg)
}

func GenerateWarn(errorTitle string, msg string) error {
	return generateLog(1, errorTitle, msg)
}

func GenerateInfo(errorTitle string, msg string) error {
	return generateLog(2, errorTitle, msg)
}

func GenerateDebug(errorTitle string, msg string) error {
	return generateLog(3, errorTitle, msg)
}
