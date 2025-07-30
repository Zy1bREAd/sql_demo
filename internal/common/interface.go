package common

import "context"

type QTasker interface {
	ExcuteTask(context.Context)
}
