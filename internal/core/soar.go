package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sql_demo/internal/utils"
)

// Soar Result
type SoarRules struct {
	Position int
	Item     string
	Severity string
	Summary  string
	Content  string
	Case     string
}

type SoarResult struct {
	Data map[string][]SoarRules
}

type SoarAnalyzer struct {
	IsOnlySynatxCheck bool
	ReportFormat      string // all,text,html,json,markdown (default:markdown)
	CommandPath       string
	Command           string // 命令名字
	SQLContent        string // 需要分析的SQL文件
}

type SoarOptions func(*SoarAnalyzer)

func WithReportFormat(format string) SoarOptions {
	return func(sa *SoarAnalyzer) {
		sa.ReportFormat = format
	}
}

func WithCommand(cmd string) SoarOptions {
	if cmd == "" {
		cmd = "soar"
	}
	return func(sa *SoarAnalyzer) {
		sa.Command = cmd
	}
}

func WithCommandPath(cmdPath string) SoarOptions {
	if cmdPath == "" {
		cmdPath = "/tmp"
	}
	return func(sa *SoarAnalyzer) {
		sa.CommandPath = cmdPath
	}
}

func WithSQLContent(sqlRaw string) SoarOptions {
	return func(sa *SoarAnalyzer) {
		sa.SQLContent = sqlRaw
	}
}

// 构造一个Soar分析器
func NewSoarAnalyzer(opts ...SoarOptions) *SoarAnalyzer {
	soar := &SoarAnalyzer{
		IsOnlySynatxCheck: false, // 默认关闭
	}
	for _, opt := range opts {
		opt(soar)
	}
	return soar
}

// 构造Shell环境执行Soar命令
func (soar *SoarAnalyzer) getShellCmd() string {
	var execCmd string
	if soar.SQLContent != "" {
		execCmd += fmt.Sprintf(`echo -e "%s"`, soar.SQLContent)
	}
	execCmd += fmt.Sprintf(` | ./%s`, soar.Command)

	if soar.ReportFormat != "" {
		execCmd += fmt.Sprintf(" -report-type %s", soar.ReportFormat)
	}
	if soar.IsOnlySynatxCheck {
		execCmd += " -only-syntax-check"
	}
	return execCmd

}

// 执行命令进行分析SQL
func (soar *SoarAnalyzer) Analysis() ([]byte, error) {
	exist := soar.IsExistSoar()
	if !exist {
		return nil, utils.GenerateError("SoarNotFound", "Soar is not exist")
	}
	// 开始分析
	execCmd := soar.getShellCmd()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "bash", "-c", execCmd)
	cmd.Dir = soar.CommandPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 错误信息要捕获output
		return nil, utils.GenerateError("SoarAnalysisErr", err.Error()+string(output))
	}
	return output, nil
}

// 检查是否存在SOAR该工具
func (soar *SoarAnalyzer) IsExistSoar() bool {
	_, err := os.Stat(soar.CommandPath + "/" + soar.Command)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		utils.ErrorPrint("SOARErr", err.Error())
		return false
	}
	return true
}
