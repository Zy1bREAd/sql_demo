package dbo

import (
	"time"

	"gorm.io/gorm"
)

const (
	DEFAULTUSER = 0
	GITLABUSER  = 2

	// User Role
	AdministratorRole = 0
	DeveloperRole     = 1
	GuestRole         = 2
)

type User struct {
	ID             uint      `gorm:"primaryKey"`
	UserType       uint      `gorm:"type:smallint;not null"` // 0=Default User; 2=GitLab User
	GitLabIdentity uint      `gorm:"uniqueIndex"`            // Gitlab User的身份标识
	Name           string    `gorm:"type:varchar(255);not null"`
	UserName       string    `gorm:"type:varchar(255);"`
	Password       string    `gorm:"type:varchar(255);not null"`
	Email          string    `gorm:"type:varchar(255);"`
	Role           int       `gorm:"type:smallint;default:2;"`
	CreateAt       time.Time `gorm:"autoCreateTime"`

	// 权限？

	// 关联
	QueryAuditLogs []AuditRecordV2 `gorm:"foreignKey:UserID"`
}

type AuditRecordV2 struct {
	ID uint `gorm:"primaryKey"`
	// 关联Ticket表
	TicketID int64  `gorm:""` // 相当于链路ID
	Ticket   Ticket `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:TicketID;references:UID"`

	TaskID    string    `gorm:"type:varchar(255);index"`
	EventType string    `gorm:"type:varchar(64);not null"`
	Payload   string    `gorm:""` // 记录审计的载体，以JSON格式
	TaskKind  int       `gorm:"type:smallint"`
	CreateAt  time.Time `gorm:"type:datetime(0);autoCreateTime"`
	// 关联User表
	User   User `gorm:"not null;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:UserID;constraintName:fk_audit_record_user_v2"`
	UserID uint

	// 关联GitLab
	ProjectID uint `gorm:"type:int"`
	IssueID   uint `gorm:"type:int"`

	// 条件筛选
	StartTime string `gorm:"-"`
	EndTime   string `gorm:"-"`
}

func (audit *AuditRecordV2) TableName() string {
	return "audit_logs_v3"
}

type TempResultMap struct {
	UID           string    `gorm:"primaryKey;"`
	TicketID      int64     `gorm:"not null"`
	IsDeleted     uint8     `gorm:"default:0;type:smallint"`
	IsAllowExport bool      `gorm:"default:false"`
	CreateAt      time.Time `gorm:"type:datetime(0);autoCreateTime"`
	ExpireAt      time.Time `gorm:"type:datetime(0)"`
}

func (temp *TempResultMap) TableName() string {
	return "temp_results"
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
type QueryDataBase struct {
	ID              uint      `gorm:"primaryKey"`
	UID             string    `gorm:"type:varchar(36);not null,uniqueIndex"`
	Name            string    `gorm:"type:varchar(128);not null;"`
	Service         string    `gorm:"type:varchar(128);not null;uniqueIndex:idx_env_app"`
	Host            string    `gorm:"type:varchar(128);default:localhost"`
	Port            string    `gorm:"type:varchar(64);default:3306;"`
	User            string    `grom:"type:varchar(128);deafult:root;"`
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
	UID            int64  `gorm:"uniqueIndex;not null"` // 雪花ID
	TaskID         string `gorm:"type:varchar(64)"`
	Status         string `gorm:"type:varchar(64);not null;index"`
	Source         string `gorm:"type:varchar(64);default:normal"` // 用于标识Ticket的来源。比如普通API请求的就是normal，而还有一种就是gitlab的
	SourceRef      string `grom:"varchar(64);index;not null"`      // 作为关键来源标识（一组流程的唯一标识）
	IdemoptencyKey string `gorm:"type:varchar(64);uniqueIndex"`
	AuthorID       uint   `gorm:"not null"` // 表示该Ticket所属者
	UserForKey     User   `gorm:"not null;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:AuthorID;references:ID"`
	ProjectID      int    `gorm:"uniqueIndex:idx_ticket;"`
	IssueID        int    `gorm:"uniqueIndex:idx_ticket;"`
	Link           string `gorm:"type:varchar(255)"`
	gorm.Model
}

func (t *Ticket) TableName() string {
	return "t_ticket"
}
