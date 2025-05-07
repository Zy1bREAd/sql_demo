package apis

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

var initOnce sync.Once

// Application环境变量配置
type appEnvConfig struct {
	DBEnv        map[string]MySQLConfig `yaml:"db"`
	DataMaskMode string                 `yaml:"data_mask"`
	WebSrvEnv    WebServerConfig        `yaml:"web"`
}

type WebServerConfig struct {
	Addr   string       `yaml:"addr"`
	Port   string       `yaml:"port"`
	TLSEnv WebTLSConfig `yaml:"tls"`
}

type WebTLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    string `yaml:"port"`
	Key     string `yaml:"key"`
	Cert    string `yaml:"cert"`
}

var appConfig *appEnvConfig

// 初始化环境变量配置
func InitEnv() {
	initOnce.Do(func() {
		f, err := os.ReadFile("config/env.yaml")
		if err != nil {
			panic(GenerateError("Init Error", err.Error()))
		}
		err = yaml.Unmarshal(f, &appConfig)
		if err != nil {
			panic(GenerateError("Init Error", err.Error()))
		}
		fmt.Println("appConfig=", appConfig)
		// 加载数据遮罩规则
		InitDataMaskConfig()

	})
}

func getAppConfig() *appEnvConfig {
	if appConfig == nil {
		InitEnv()
	}
	return appConfig
}
