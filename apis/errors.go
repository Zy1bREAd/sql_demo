package apis

import (
	"errors"
	"fmt"
	"log"
	"time"
)

func ErrorRecover() {
	if err := recover(); err != nil {
		now := time.Now()
		log.Printf("[%s][ERRRO] - %s", now.Format("2006-01-02T15:04:05"), err)
		// panic(err)
	}
}

func GenerateError(errorTitle string, msg string) error {
	formatErrorMsg := fmt.Sprintf("[ERROR] <%s> %s", errorTitle, msg)
	return errors.New(formatErrorMsg)
}
