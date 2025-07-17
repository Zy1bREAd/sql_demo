package apis

import "time"

type User struct {
	ID             uint      `gorm:"primaryKey"`
	UserType       uint      `gorm:"type:smallint;not null"` // 0=Default User; 2=GitLab User
	GitLabIdentity uint      `gorm:"uniqueIndex"`            // Gitlab User的身份标识
	Name           string    `gorm:"type:varchar(255);not null"`
	UserName       string    `gorm:"type:varchar(255);"`
	Password       string    `gorm:"type:varchar(255);not null"`
	Email          string    `gorm:"type:varchar(255);"`
	CreateAt       time.Time `gorm:"autoCreateTime"`

	// 权限？

	// 关联
	QueryAuditLogs []AuditRecord `gorm:"foreignKey:UserID"`
}

func (u *User) ToUserResp() UserResp {
	return UserResp{
		ID:    u.ID,
		Name:  u.Name,
		Email: u.Email,
	}
}

// 专用响应User结构体
type UserResp struct {
	ID    uint   `json:"id"`
	Name  string `json:"username"`
	Email string `json:"email"`
}

type AuditRecord struct {
	ID     uint   `gorm:"primaryKey"`
	TaskID string `gorm:"type:varchar(255);not null;uniqueIndex"`
	// DML          string    `gorm:"type:char(64);"`
	SQLStatement string    `gorm:"not null"`
	DBName       string    `gorm:"type:varchar(255)"`
	TimeStamp    time.Time `gorm:"type:datetime(0);autoCreateTime"`
	IsExported   uint8     `gorm:"default:0;type:smallint;"`
	ExportTime   time.Time `gorm:"type:datetime(0);"`
	// 查询的环境
	Env string `gorm:"type:char(64)"`
	// 关联表
	User   User `gorm:"not null;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:UserID;constraintName:fk_audit_record_user"`
	UserID uint

	// 关联GitLab
	// ProjectID uint `gorm:"type:int"`
	// IssueID   uint `gorm:"type:int"`
}

func (audit *AuditRecord) TableName() string {
	return "query_audit_logs"
}

type AuditRecordV2 struct {
	ID        uint      `gorm:"primaryKey"`
	TaskID    string    `gorm:"type:varchar(255);not null;index"` // 相当于链路ID
	EventType string    `gorm:"type:varchar(64);not null"`
	Payload   string    `gorm:""` // 记录审计的载体，以JSON格式
	CreatAt   time.Time `gorm:"type:datetime(0);autoCreateTime"`

	// 关联User表
	User   User `gorm:"not null;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:UserID;constraintName:fk_audit_record_user"`
	UserID uint

	// 关联GitLab
	ProjectID uint `gorm:"type:int"`
	IssueID   uint `gorm:"type:int"`
}

func (audit *AuditRecordV2) TableName() string {
	return "audit_logs_v3"
}

type TempResultMap struct {
	UUKey         string    `gorm:"primaryKey"`
	TaskId        string    `gorm:"type:varchar(255);not null;uniqueIndex"`
	CreateAt      time.Time `gorm:"type:datetime(0);autoCreateTime"`
	ExpireAt      time.Time `gorm:"type:datetime(0)"`
	IsDeleted     uint8     `gorm:"default:0;type:smallint"`
	IsAllowExport bool      `gorm:"default:false"`
}

func (temp *TempResultMap) TableName() string {
	return "temp_results"
}
