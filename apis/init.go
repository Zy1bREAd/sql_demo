package apis

import (
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
	SSOEnv       SSOConfig              `yaml:"sso"`
	ExportEnv    ExportConfig           `yaml:"export"`
	GitLabEnv    GitLabConfig           `yaml:"gitlab"`
	WeixinEnv    WeixinConfig           `yaml:"weixin"`
	ApprovalMap  map[string]uint        `yaml:"approval_list"`
}

type ExportConfig struct {
	FilePath     string `yaml:"file_path"`
	HouseKeeping int    `yaml:"housekeeping"`
}

type WebServerConfig struct {
	Addr     string       `yaml:"addr"`
	Port     string       `yaml:"port"`
	HostName string       `yaml:"hostname"`
	TLSEnv   WebTLSConfig `yaml:"tls"`
}

type WebTLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    string `yaml:"port"`
	Key     string `yaml:"key"`
	Cert    string `yaml:"cert"`
}

type SSOClientConfig struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

type SSOConfig struct {
	RedirectURL string          `yaml:"redirect_url"`
	ClientAPI   string          `yaml:"client_api"`
	ClientEnv   SSOClientConfig `yaml:"client"`
	EndpointEnv EndpointConfig  `yaml:"endpoint"`
}
type EndpointConfig struct {
	AuthURL  string `yaml:"auth_url"`
	TokenURL string `yaml:"token_url"`
}
type WebhookConfig struct {
	SceretToken string `yaml:"secret_token"`
}

type GitLabConfig struct {
	AccessToken string        `yaml:"access_token"`
	URL         string        `yaml:"url"`
	WebhookEnv  WebhookConfig `yaml:"webhook"`
	RobotUserId uint          `yaml:"handle_robot_id"`
}

type WeixinConfig struct {
	InformWebhook string `yaml:"inform_webhook"`
}

// type ApprovalConfig struct{

// }

var appConfig *appEnvConfig

// 初始化环境变量配置
func InitEnv() {
	initOnce.Do(func() {
		f, err := os.ReadFile("./config/env.yaml")
		if err != nil {
			panic(GenerateError("Init Error", err.Error()))
		}
		err = yaml.Unmarshal(f, &appConfig)
		if err != nil {
			panic(GenerateError("Init Error", err.Error()))
		}
		// log.Println("appConfig=", appConfig)
		// 加载数据遮罩规则
		InitDataMaskConfig()

	})
}

func GetAppConfig() *appEnvConfig {
	if appConfig == nil {
		InitEnv()
	}
	return appConfig
}
