package conf

import (
	"os"
	"sql_demo/internal/utils"
	"sync"

	"gopkg.in/yaml.v3"
)

// Application环境变量配置
type BaseConfig struct {
	DBEnv        map[string]DBConfigMySQL `yaml:"db"`
	DataMaskMode string                   `yaml:"data_mask"`
	WebSrvEnv    WebServerConfig          `yaml:"web"`
	SSOEnv       SSOConfig                `yaml:"sso"`
	ExportEnv    ExportConfig             `yaml:"export"`
	GitLabEnv    GitLabConfig             `yaml:"gitlab"`
	WeixinEnv    WeixinConfig             `yaml:"weixin"`
	ApprovalMap  map[string]uint          `yaml:"approval_list"`
	AIEnv        AIConfig                 `yaml:"ai"`
}

type DBConfigMySQL struct {
	MaxConn  int      `yaml:"max_conn"`
	IdleTime int      `yaml:"idle_time"`
	Name     string   `yaml:"name"`
	Host     string   `yaml:"host"`
	Password string   `yaml:"password"`
	User     string   `yaml:"user"`
	Port     string   `yaml:"port"`
	DSN      string   `yaml:"dsn"`
	Exclude  []string `yaml:"exclude"`
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

type AIConfig struct {
	URL        string `yaml:"url"`
	Model      string `yaml:"model"`
	SecretName string `yaml:"secret_name"`
	SecretKey  string `yaml:"secret_key"`
}

// 定义读取配置接口
type ConfigReader interface {
	GetBaseConfig() *BaseConfig
	GetDataMaskConfig() *DataMaskConfig
}

var initOnce sync.Once
var appConf *AppConfig

type AppConfig struct {
	baseConfig     *BaseConfig
	dataMaskConfig *DataMaskConfig
}

func initBaseConfig(filePath string) (*BaseConfig, error) {
	var baseConf BaseConfig
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, utils.GenerateError("InitConfError", err.Error())
	}
	err = yaml.Unmarshal(f, &baseConf)
	if err != nil {
		return nil, utils.GenerateError("InitConfError", err.Error())
	}
	return &baseConf, nil
}

// 集中初始化环境变量+其他配置
func InitAppConfig() {
	initOnce.Do(func() {
		// 读取环境变量配置App
		baseConf, err := initBaseConfig("./config/env.yaml")
		if err != nil {
			panic(utils.GenerateError("InitDMError", err.Error()))
		}
		// 读取数据遮罩配置
		dmConf, err := initDataMaskConfig("./config/data_mask_rule.yaml")
		if err != nil {
			panic(utils.GenerateError("InitDMError", err.Error()))
		}

		appConf = &AppConfig{
			baseConfig:     baseConf,
			dataMaskConfig: dmConf,
		}
	})
}

func GetAppConf() *AppConfig {
	if appConf == nil {
		panic(utils.GenerateError("AppConfigNotExist", "app config is not exist"))
	}
	return appConf
}

func (c *AppConfig) GetBaseConfig() *BaseConfig {
	return c.baseConfig
}

func (c *AppConfig) GetDataMaskConfig() *DataMaskConfig {
	return c.dataMaskConfig
}
