package dbo

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID             string    `gorm:"type:varchar(32);uniqueIndex"`
	Name           string    `gorm:"type:varchar(255);not null;index:idx_usr"`
	UserName       string    `gorm:"type:varchar(255);"`
	Kind           uint      `gorm:"type:smallint;not null;index:idx_usr"` // 0=Default User; 2=GitLab User
	Status         string    `gorm:"type:varchar(255);"`
	GitLabIdentity uint      `gorm:"uniqueIndex"`                 // Gitlab User的身份标识
	IsActive       bool      `gorm:"type:smallint;default:false"` // false-禁用 true-启用
	IsAdmin        bool      `gorm:"type:smallint;default:false"`
	Password       string    `gorm:"type:varchar(255);not null"`
	Email          string    `gorm:"type:varchar(255);"`
	CreatedAt      time.Time `gorm:"autoCreateTime"`
	UpdatedAt      time.Time `gorm:""`

	// 关联
	// QueryAuditLogs []AuditRecordV2 `gorm:"foreignKey:UserID"`
}

type AuditRecordV2 struct {
	ID uint `gorm:"primaryKey"`
	// 关联Ticket表
	// TicketID int64  `gorm:""` // 相当于链路ID
	// Ticket   Ticket `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:TicketID;references:UID"`
	TicketID  int64     `gorm:"index"`
	TaskID    string    `gorm:"type:varchar(255);index"`
	TaskKind  int       `gorm:"type:smallint"`
	EventType string    `gorm:"type:varchar(64);not null"`
	Payload   string    `gorm:""` // 记录审计的载体，以JSON格式
	CreateAt  time.Time `gorm:"type:datetime(0);autoCreateTime"`
	// 关联User表
	User   User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:UserID;references:ID"`
	UserID string

	// 关联GitLab
	ProjectID uint `gorm:"type:int"`
	IssueID   uint `gorm:"type:int"`

	// 条件筛选
	StartTime string `gorm:"-"`
	EndTime   string `gorm:"-"`
}

func (audit *AuditRecordV2) TableName() string {
	return "audit_logs"
}

type TempResult struct {
	UUKey          string    `gorm:"primaryKey;"`
	TicketID       int64     `gorm:"not null"`
	TaskID         string    `gorm:"type:varchar(255);uniqueIndex"`
	IsDeleted      bool      `gorm:"default:false"`
	IsAllowExport  bool      `gorm:"default:false"`
	IsExported     bool      `gorm:"default:false"`
	ExportPath     string    `gorm:"type:varchar(255)"`
	ExportFileName string    `gorm:"type:varchar(255)"`
	CreateAt       time.Time `gorm:"type:datetime(0);autoCreateTime"`
	ExpireAt       time.Time `gorm:"type:datetime(0)"`
	ExportAt       time.Time `gorm:"default:null"`
}

func (temp *TempResult) TableName() string {
	return "temp_results_v2"
}

// 存储管理员的数据库执行环境
type QueryEnv struct {
	ID          uint      `gorm:"primaryKey"`
	UID         string    `gorm:"type:varchar(36);not null,uniqueIndex"`
	Name        string    `gorm:"type:varchar(255);not null;uniqueIndex"`
	Tag         string    `gorm:"type:varchar(128)"`
	Description string    `gorm:"type:varchar(255)"`
	IsWrite     bool      `gorm:"default:false"`
	CreateAt    time.Time `gorm:"type:datetime(0);autoCreateTime"`
	UpdateAt    time.Time `gorm:"type:datetime(0);autoCreateTime"`
	// 一对多
	// QueryDataBases []QueryDataBase `gorm:"foreignKey:EnvID"`
}

func (temp *QueryEnv) TableName() string {
	return "query_env_info"
}

// 存储管理员的数据库执行环境
// TODO: 更名为QuerySources
type QueryDataBase struct {
	ID              uint      `gorm:"primaryKey"`
	UID             string    `gorm:"type:varchar(36);not null,uniqueIndex"`
	Name            string    `gorm:"type:varchar(128);not null;"`
	Service         string    `gorm:"type:varchar(128);not null;uniqueIndex:idx_env_app"`
	Host            string    `gorm:"type:varchar(128);default:localhost"`
	Port            string    `gorm:"type:varchar(64);default:3306;"`
	User            string    `grom:"type:varchar(128);default:root;"`
	Password        string    `gorm:"type:varchar(128);not null;"`
	ConfirmPassword string    // 校验密码
	Description     string    `gorm:"type:varchar(255)"`
	TLS             bool      `gorm:"default:false"`
	MaxConn         int       `gorm:"default:10"`
	IdleTime        int       `gorm:"default:60"`
	IsWrite         bool      `gorm:"default:false"`
	ExcludeDB       string    // 排除的数据库名
	ExcludeTable    string    // 排除的数据表名
	Salt            []byte    `gorm:"type:blob"`
	UpdateAt        time.Time `gorm:"type:datetime(0);autoCreateTime"`
	CreateAt        time.Time `gorm:"type:datetime(0);autoCreateTime"`

	EnvID     uint     `gorm:"not null;uniqueIndex:idx_env_app"`
	EnvForKey QueryEnv `gorm:"not null;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:EnvID;references:ID"`
}

func (temp *QueryDataBase) TableName() string {
	return "query_db_info"
}

// 工单表（主要是完成Ticket的状态流转）
type Ticket struct {
	UID            int64       `gorm:"not null;uniqueIndex;"` // 雪花ID
	TaskID         string      `gorm:"type:varchar(64)"`
	Status         string      `gorm:"type:varchar(64);not null;index"`
	Source         int         `gorm:"type:smallint(1);index:idx_gitlab_ticket;"` // 用于标识Ticket的来源。normal:1     gitlab:2
	SourceRef      string      `gorm:"type:varchar(64);uniqueIndex;"`             // 作为关键来源标识
	BusinessRef    string      `gorm:"type:varchar(64);index;"`                   // （一组流程的唯一标识）
	IdemoptencyKey string      `gorm:"type:varchar(64);index"`
	TaskContent    TaskContent `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:TaskContentID;references:ID"` //! 关联API Task Content
	TaskContentID  uint
	AuthorID       string // 表示该Ticket所属者
	UserForKey     User   `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:AuthorID;references:ID"`
	ProjectID      int    `gorm:"index:idx_gitlab_ticket;"`
	IssueID        int    `gorm:"index:idx_gitlab_ticket;"`
	Link           string `gorm:"type:varchar(255)"`
	gorm.Model
}

func (t *Ticket) TableName() string {
	return "t_ticket"
}

// 任务内容
type TaskContent struct {
	Env          string `gorm:"type:varchar(64);not null"`
	Service      string `gorm:"type:varchar(255);not null;index"`
	DBName       string `gorm:"type:varchar(255);not null;index"`
	Statement    string `gorm:"not null"`
	LongTime     bool   `gorm:""`
	IsExport     bool   `gorm:""`
	IsSOAR       bool   `gorm:""`
	IsAiAnalysis bool   `gorm:""`
	// AuthorID
	gorm.Model
}

func (t *TaskContent) TableName() string {
	return "t_task_content"
}

// // 审批相关规则
// type Roles struct {
// 	gorm.Model
// 	Name        string `gorm:"type:varchar(255);not null;uniqueIndex"`
// 	Priority    int    `gorm:""`
// 	Description string `gorm:""`
// }

// func (t *Roles) TableName() string {
// 	return "t_roles"
// }
