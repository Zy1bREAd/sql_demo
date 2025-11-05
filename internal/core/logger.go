package core

import (
	"log"
	"os"
	"sql_demo/internal/conf"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var zapLogger *zap.Logger

func InitManualLogger() {
	// 自定义时间戳
	timeEncoder := func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02 15:04:05"))
	}

	encConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseColorLevelEncoder,
		EncodeTime:     timeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder, // 不会生效，因为 CallerKey 为空
	}

	// ! 不使用预设的EncoderConfig，使用自定义EncoderConfig
	// consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	// fileEncoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	consoleEncoder := zapcore.NewConsoleEncoder(encConfig)
	fileEncoder := zapcore.NewJSONEncoder(encConfig)

	// 日志文件初始化
	appConf := conf.GetAppConf()
	fileWirter, err := os.OpenFile(appConf.BaseConfig().GlobalEnv.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	consoleWriteSyncer := zapcore.AddSync(os.Stdout)
	fileWriteSyncer := zapcore.AddSync(fileWirter)
	coreLog := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleWriteSyncer, zapcore.DebugLevel),
		zapcore.NewCore(fileEncoder, fileWriteSyncer, zapcore.InfoLevel),
	)

	zapLogger = zap.New(coreLog)

}

func InitSimplyLogger() {
	l, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	zapLogger = l
}

func GetLogger() *zap.Logger {
	return zapLogger
}

func CloseLogger() {
	err := zapLogger.Sync()
	if err != nil {
		log.Println(err)
	}
}
