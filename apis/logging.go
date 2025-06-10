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

func DebugLogging(errorTitle string, msg any) {
	if assertVal, ok := msg.(string); ok {
		fmt.Println(generateLog(3, errorTitle, assertVal))
	} else if assertVal, ok := msg.(int); ok {
		fmt.Println(generateLog(3, errorTitle, string(assertVal)))
	} else {
		fmt.Println(generateLog(3, "LogMsgType", "msg type is invaild"))
	}
}
