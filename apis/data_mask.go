package apis

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	"slices"

	"gopkg.in/yaml.v3"
)

var dataMaskConfig *DataMaskConfig

type DataMaskConfig struct {
	RuleConfig map[string]RuleConfig `yaml:"data-mask"`
	// valid      bool                  // 判断结构体是否有效
}

type RuleConfig struct {
	IllegalFields []string    `yaml:"illegal_fields"`
	Mode          string      `yaml:"mode"`
	Regex         bool        `yaml:"regex"`
	MaskValue     string      `yaml:"mask_value"`
	MatchRange    RangeConfig `yaml:"range"`
}

type RangeConfig struct {
	Start int `yaml:"start"`
	End   int `yaml:"end"`
}

func InitDataMaskConfig() {
	if dataMaskConfig == nil {
		err := loadInRule()
		if err != nil {
			panic(err)
		}
	}
}

func loadInRule() error {
	f, err := os.ReadFile("config/data_mask_rule.yaml")
	if err != nil {
		return GenerateError("LoadIn Failed", err.Error())
	}
	err = yaml.Unmarshal(f, &dataMaskConfig)
	fmt.Println("datamasking=", dataMaskConfig.RuleConfig)
	if err != nil {
		return GenerateError("LoadIn Failed", err.Error())
	}
	return nil
}

type Desensitizer interface {
	Mask(col string, fieldVal []byte) (string, error)
}

type FullDesensitizer struct {
	Rule RuleConfig
}

// 全加密模式
func (f *FullDesensitizer) Mask(col string, fieldVal []byte) (string, error) {
	// 后续判断是否启用正则
	fmt.Println("debug>>>", f.Rule.IllegalFields, col, f.Rule)
	if slices.Contains(f.Rule.IllegalFields, col) {
		return f.Rule.MaskValue, nil
	}
	return string(fieldVal), nil
}

type PartialDesensitizer struct {
	Rule RuleConfig
}

// 部分加密模式
func (p *PartialDesensitizer) Mask(col string, fieldVal []byte) (string, error) {
	if !slices.Contains(p.Rule.IllegalFields, col) {
		return string(fieldVal), nil
	}
	if len(fieldVal) > p.Rule.MatchRange.End {
		for i := p.Rule.MatchRange.Start; i <= p.Rule.MatchRange.End; i++ {
			fieldVal[i] = 42
		}
		return string(fieldVal), nil
	}
	return "****", nil
	// log.Println("数据脱敏失败，超过字节长度")
	// return string(fieldVal), GenerateError("MaskFailed", "range is not match bytes length")
}

// 数据遮罩处理
func DataMaskHandle(col string, fieldVal *sql.RawBytes) string {
	mode := getAppConfig().DataMaskMode
	// 根据你选择的mask模式返回接口实例，使用接口方法区执行dataMask操作。
	er := getDesensitizer(mode)
	maskVal, err := er.Mask(col, *fieldVal)
	if err != nil {
		log.Println("数据脱敏操作有问题", err.Error())
	}
	return maskVal
}

func matchRuleConfig(mode string) RuleConfig {
	for _, ruleConfig := range dataMaskConfig.RuleConfig {
		if mode == ruleConfig.Mode {
			return ruleConfig
		}
	}
	return RuleConfig{}
}

func getDesensitizer(mode string) Desensitizer {
	lowerStr := strings.ToLower(mode)
	rule := matchRuleConfig(lowerStr)
	switch {
	case lowerStr == "full":
		return &FullDesensitizer{Rule: rule}
	case lowerStr == "partial":
		return &PartialDesensitizer{Rule: rule}
	default:
		log.Println("没有匹配到数据遮罩模式")
		return nil
	}
}
