package api

import (
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
)

// DTO: Data Transfer Object + Service Layer

type QueryDataBaseDTO struct {
	EnvID             uint            `json:"env_id"` // 关键指定EnvID
	IsWrite           bool            `json:"is_write"`
	Name              string          `json:"name"`
	UID               string          `json:"uid"`
	EnvName           string          `json:"env_name"`
	Service           string          `json:"service"`
	Desc              string          `json:"description,omitempty"`
	CreateAt          string          `json:"create_at"`
	UpdateAt          string          `json:"update_at"`
	ExcludeDB         []string        `json:"exclude_db"`    // 排除的数据库名
	ExcludeTable      []string        `json:"exclude_table"` // 排除的数据表名
	Connection        dbo.ConnectInfo `json:"connection"`    // 连接信息
	ConfirmedPassword string          `json:"confirm_pwd"`   // 二次验证新密码
}

type QueryEnvDTO struct {
	IsWrite  bool     `json:"is_write"`
	UID      string   `json:"uid"`
	Name     string   `json:"name"`
	Tag      []string `json:"tag"`
	Desc     string   `json:"description"`
	CreateAt string   `json:"create_at"`
	UpdateAt string   `json:"update_at"`
}

type AuditRecordDTO struct {
	ProjectID uint   `json:"project_id"`
	IssueID   uint   `json:"issue_id"`
	UserID    uint   `json:"user_id"`
	TaskType  int    `json:"task_type"`
	TicketID  int64  `json:"ticket_id"`
	TaskID    string `json:"task_id"`
	UserName  string `json:"username"`
	EventType string `json:"event_type"`
	Payload   string `json:"payload"`
	CreateAt  string `json:"create_at"`
	// 时间范围筛选条件项
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
}

type TicketDTO struct {
	TaskContentID  uint           `json:"-"`
	TaskContent    SQLTaskRequest `json:"task_content"`
	TaskID         string         `json:"task_id"`
	Status         string         `json:"status"`
	SourceRef      string         `json:"source_ref"`   // 标识来源
	BusinessRef    string         `json:"business_ref"` // 针对API调用作为一组流程的聚合
	IdemoptencyKey string         `json:"idem_key"`
	UID            int64          `json:"uid"`       // 雪花ID
	Source         int            `json:"source"`    // 用于标识Ticket的来源。
	AuthorID       uint           `json:"author_id"` // 表示该Ticket所属者
	ProjectID      uint           `json:"project_id"`
	IssueIID       uint           `json:"issue_iid"`
}

type TicketResponse struct {
	SourceRef      string `json:"source_ref"`
	IdemoptencyKey string `json:"idem_key"`
	BusinessRef    string `json:"businessRef"` // 作为关键来源标识（一组流程的唯一标识）
}

// TicketStatusStats 票据状态统计 DTO（数据传输对象）
type TicketStatusStatsDTO struct {
	CreatedCount        int `json:"created_count"`         // 创建状态数量
	ApprovalPassedCount int `json:"approval_passed_count"` // 审批通过数量
	ApprovalRejectCount int `json:"approval_reject_count"` // 审批拒绝数量
	ExecutePendingCount int `json:"execute_pending_count"` // 执行中（待处理）数量
	PendingCount        int `json:"pending_count"`         // 待处理数量
	CompletedCount      int `json:"completed_count"`       // 已完成数量
	FailedCount         int `json:"failed_count"`          // 失败数量
	TotalCount          int `json:"total_count"`
}

// 请求SQL任务的 DTO
type SQLTaskRequest struct {
	ID           uint   `json:"-"`
	Env          string `json:"env" validate:"omitempty"`
	Service      string `json:"service" validate:"omitempty"`
	DBName       string `json:"db_name" validate:"omitempty"`
	Statement    string `json:"statement" validate:"omitempty"` // TODO: 后期支持切片（数组）形式
	LongTime     bool   `json:"long_time"`
	IsExport     bool   `json:"is_export"`
	IsSOAR       bool   `json:"is_soar"`
	IsAiAnalysis bool   `json:"is_aianalysis"`
}

// 校验
func (dto SQLTaskRequest) Validate() error {
	va := utils.NewValidator()
	err := va.Struct(&dto)
	if err != nil {
		return err
	}
	return nil
}

// GitLab Issue内容
type IssueTaskContent struct {
	SQLTaskRequest
	Action string `json:"action"`
	Remark string `json:"remark,omitempty"`
}

// 校验
func (dto IssueTaskContent) Validate() error {
	va := utils.NewValidator()
	err := va.Struct(&dto)
	if err != nil {
		return err
	}
	return nil
}

type SQLTaskResponse struct {
	Action      string `json:"action" validate:"required"`
	BusinessRef string `json:"business_ref" validate:"required"`
	OperateTime string `json:"operate_time" validate:"required"`
	Operator    string `json:"operator"`
	Remark      string `json:"remark"`
}

// 请求SQL任务的 DTO
type SQLTaskReview struct {
	BusinessRef string `json:"business_ref" validate:"required"` // 业务标识
	Reason      string `json:"reason"`                           // 驳回原因
	Action      int    `json:"action" validate:"required"`       // 上线(2)、审批(1)、驳回(0)等
}

// 校验
func (dto SQLTaskReview) Validate() error {
	va := utils.NewValidator()
	err := va.Struct(&dto)
	if err != nil {
		return err
	}
	return nil
}

type TempResultDTO struct {
	UUKey          string
	TaskID         string
	ExportPath     string
	ExportFileName string
	TicketID       int64
	IsDeleted      bool
	IsAllowExport  bool
	IsExported     bool
}

// 临时数据集响应体DTO
type TempResultResponse struct {
	// Data      *core.SQLResultGroupV2 `json:"data"`
	Data      []*dbo.SQLResult `json:"data"`
	TaskID    string           `json:"task_id"`
	IsExport  bool             `json:"is_export"`
	IsExpried bool             `json:"is_expried"`
}

func (dto *TicketStatusStatsDTO) StatsCount() (map[string]int, error) {
	var t dbo.Ticket
	resultMap, err := t.StatsCount()
	if err != nil {
		return nil, err
	}
	return resultMap, nil
}

// 导出结果集的请求DTO
type ExportResultRequest struct {
	TaskID    string `json:"task_id" query:"task_id"` // TaskID UUID v4
	TicketID  int64  `json:"ticket_id" query:"ticket_id"`
	ResultIdx int    `json:"result_idx" query:"result_idx"` // 用于仅导出指定结果集的索引（前端传递）
	IsOnly    bool   `json:"is_only" query:"is_only"`
}
