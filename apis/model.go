package apis

import "time"

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Name     string `gorm:"type:varchar(255);not null"`
	Password string `gorm:"type:varchar(255);not null"`
	Email    string `gorm:"type:varchar(255);not null;uniqueIndex"`
	CreateAt time.Time

	// 权限？

	// 关联
	QueryAuditLogs []QueryAuditLog `gorm:"foreignKey:UserID"`
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

type QueryAuditLog struct {
	ID           uint   `gorm:"primaryKey"`
	TaskID       string `gorm:"type:varchar(255);not null;uniqueIndex"` // 为什么增加taskid 因为后期可能通过taskid检索日志找到一些执行的过程。
	UserID       string
	SQLStatement string    `gorm:"not null"`
	DBName       string    `gorm:"type:varchar(255)"`
	TimeStamp    time.Time `gorm:"autoCreateTime"`

	// 关联表
	User User `gorm:"not null;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:UserID"`
}
