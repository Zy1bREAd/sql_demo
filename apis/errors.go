package apis

import (
	"errors"
	"fmt"
	"log"
	"time"
)

func ErrorRecover() {
	if err := recover(); err != nil {
		log.Printf("[ERRRO] - [%s] - %s", time.Now().GoString(), err)
		// panic(err)
	}
}

func GenerateError(errorTitle string, msg string) error {
	formatErrorMsg := fmt.Sprintf("<%s> %s", errorTitle, msg)
	return errors.New(formatErrorMsg)
}
