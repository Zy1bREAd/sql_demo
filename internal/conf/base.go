package conf

import (
	"fmt"
	"os"
	"sql_demo/internal/utils"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Application环境变量配置
type BaseConfig struct {
	DBEnv       map[string]DBConfigMySQL `yaml:"db"`
	DataMask    DataMaskConfig           `yaml:"data_mask"`
	WebSrvEnv   WebServerConfig          `yaml:"web"`
	SSOEnv      SSOConfig                `yaml:"sso"`
	ExportEnv   ExportConfig             `yaml:"export"`
	GitLabEnv   GitLabConfig             `yaml:"gitlab"`
	WeixinEnv   WeixinConfig             `yaml:"weixin"`
	ApprovalMap map[string]uint          `yaml:"approval_list"`
	AIEnv       AIConfig                 `yaml:"ai"`
}

type DataMaskConfig struct {
	Mode     string `yaml:"mode" default:"none"`
	FileName string `yaml:"file_name" default:"data_mask.conf"`
	FilePath string `yaml:"file_path" default:"./confg/rule/"`
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
	base    *BaseConfig
	dasMask *MaskRules
}

// 设置默认值
func (b *BaseConfig) setDefaultVal() {
	// 数据遮罩
	b.DataMask = DataMaskConfig{
		Mode:     "none",
		FileName: "data_mask.yaml",
		FilePath: "./config/rule",
	}

	b.WebSrvEnv = WebServerConfig{
		Addr:     "localhost",
		Port:     "21899",
		HostName: "localhost",
		TLSEnv: WebTLSConfig{
			Enabled: false,
			Port:    "22899",
			Key:     "./config/tls/ssl.key",
			Cert:    "./config/tls/ssl.crt",
		},
	}

	b.ExportEnv = ExportConfig{
		FilePath:     "./tmp",
		HouseKeeping: 100,
	}
}

func initBaseConfig(filePath string) (*BaseConfig, error) {
	var baseConf BaseConfig
	baseConf.setDefaultVal()

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
		// ! 基础配置
		baseConf, err := initBaseConfig("/opt/oceanwang/golang/sql_demo/config/env.yaml")
		if err != nil {
			panic(utils.GenerateError("InitDMError", err.Error()))
		}
		// 读取数据遮罩配置
		var dmConfPath string
		if strings.HasSuffix(baseConf.DataMask.FilePath, "/") {
			dmConfPath = baseConf.DataMask.FilePath + baseConf.DataMask.FileName
		} else {
			dmConfPath = baseConf.DataMask.FilePath + "/" + baseConf.DataMask.FileName
		}
		fmt.Println("debug print mask config path", dmConfPath)
		dmConf, err := initDataMaskConfig(dmConfPath)
		if err != nil {
			panic(utils.GenerateError("InitDMError", err.Error()))
		}

		appConf = &AppConfig{
			base:    baseConf,
			dasMask: dmConf,
		}
	})
}

func GetAppConf() *AppConfig {
	if appConf == nil {
		panic(utils.GenerateError("AppConfInitErr", "app config is not init"))
	}
	return appConf
}

func (c *AppConfig) GetBaseConfig() *BaseConfig {
	return c.base
}

func (c *AppConfig) GetDataMaskConfig() *MaskRules {
	return c.dasMask
}
