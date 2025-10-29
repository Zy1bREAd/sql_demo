package conf

import (
	"database/sql"
	"log"
	"os"
	"regexp"
	"sql_demo/internal/utils"
	"strings"

	"slices"

	"gopkg.in/yaml.v3"
)

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

// 数据遮罩配置
type MaskRules map[string]RuleConfig

func initDataMaskConfig(filePath string) (*MaskRules, error) {
	var dmConf MaskRules
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, utils.GenerateError("LoadIn Failed", err.Error())
	}
	err = yaml.Unmarshal(f, &dmConf)
	utils.DebugPrint("DataMaskRule", dmConf)
	if err != nil {
		return nil, utils.GenerateError("LoadIn Failed", err.Error())
	}
	return &dmConf, nil
}

type Desensitizer interface {
	Mask(col string, fieldVal []byte) (string, error)
}

type FullDesensitizer struct {
	Rules RuleConfig
}

// 全加密模式（顺序：精准匹配 -> 正则匹配）
func (f *FullDesensitizer) Mask(col string, fieldVal []byte) (string, error) {
	rule := f.Rules
	if slices.Contains(rule.IllegalFields, col) {
		return rule.MaskValue, nil
	}
	if rule.Regex {
		for _, illegalRegex := range rule.IllegalFields {
			re, err := regexp.Compile(illegalRegex)
			if err != nil {
				log.Println("Regex Pattern is invalid")
				return "", err
			}
			if re.MatchString(col) {
				return rule.MaskValue, nil
			}
			continue
		}
	}
	return string(fieldVal), nil
}

type PartialDesensitizer struct {
	Rules []RuleConfig
}

// 部分加密模式
func (p *PartialDesensitizer) Mask(col string, fieldVal []byte) (string, error) {
	for _, rule := range p.Rules {
		if slices.Contains(rule.IllegalFields, col) {
			if len(fieldVal) > rule.MatchRange.End {
				for i := rule.MatchRange.Start; i <= rule.MatchRange.End; i++ {
					fieldVal[i] = 42
				}
				continue
			}
			return "****", nil
		}
		if rule.Regex {
			for _, illegalRegex := range rule.IllegalFields {
				re, err := regexp.Compile(illegalRegex)
				if err != nil {
					log.Println("Regex Pattern is invalid")
					return "", err
				}
				if re.MatchString(col) {
					if len(fieldVal) > rule.MatchRange.End {
						for i := rule.MatchRange.Start; i <= rule.MatchRange.End; i++ {
							fieldVal[i] = 42
						}
						continue
					}
					return "****", nil
				}
				continue
			}
		}
		continue
	}
	// 跳出循环统一返回的是原值
	return string(fieldVal), nil
}

// !数据遮罩核心处理
func DataMaskHandle(col string, fieldVal *sql.RawBytes) string {
	appConf := GetAppConf()
	mode := appConf.GetBaseConfig().DataMask.Mode
	// 根据你选择的mask模式返回接口实例，使用接口方法区执行dataMask操作。
	er := getDesensitizer(mode)
	if er == nil {
		// none 模式
		return string(*fieldVal)
	}
	maskVal, err := er.Mask(col, *fieldVal)
	if err != nil {
		log.Println("数据脱敏操作有问题", err.Error())
	}
	return maskVal
}

// 按需加载数据遮罩配置
func matchRuleConfig(mode string) []RuleConfig {
	appConf := GetAppConf()
	dmConf := appConf.GetDataMaskConfig()
	ruleList := []RuleConfig{}
	for _, ruleConfig := range *dmConf {
		if mode == ruleConfig.Mode {
			ruleList = append(ruleList, ruleConfig)
		}
	}
	return ruleList
}

func getDesensitizer(mode string) Desensitizer {
	lowerStr := strings.ToLower(mode)
	rules := matchRuleConfig(lowerStr)
	switch {
	case lowerStr == "full":
		// 目前仅返回第一个匹配的
		if len(rules) > 0 {
			return &FullDesensitizer{Rules: rules[0]}
		}
		return &FullDesensitizer{Rules: RuleConfig{}}
	case lowerStr == "partial":
		return &PartialDesensitizer{Rules: rules}
	default:
		log.Println("数据遮罩模式为 none")
		return nil
	}
}
