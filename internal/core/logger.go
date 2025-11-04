package core

import (
	"log"
	"os"
	"sql_demo/internal/conf"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var zapLogger *zap.Logger

func InitManualLogger() {
	consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileEncoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())

	// 日志文件初始化
	appConf := conf.GetAppConf()
	fileWirter, err := os.Open(appConf.BaseConfig().GlobalEnv.LogPath)
	if err != nil {
		panic(err)
	}

	consoleWriteSyncer := zapcore.AddSync(os.Stdout)
	fileWriteSyncer := zapcore.AddSync(fileWirter)
	coreLog := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleWriteSyncer, zapcore.DebugLevel),
		zapcore.NewCore(fileEncoder, fileWriteSyncer, zapcore.InfoLevel),
	)

	zapLogger = zap.New(coreLog, zap.AddCaller())
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
