package apis

import "time"

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Name     string `gorm:"type:varchar(255);not null"`
	Password string `gorm:"type:varchar(255);not null"`
	Email    string `gorm:"type:varchar(255);not null;uniqueIndex"`
	CreateAt time.Time
}

type QueryAuditLog struct {
	ID           uint      `gorm:"primaryKey"`
	TaskID       string    `gorm:"not null;uniqueIndex"` // 为什么增加taskid 因为后期可能通过taskid检索日志找到一些执行的过程。
	UserID       string    `gorm:"not null;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:Handler"`
	SQLStatement string    `gorm:"not null"`
	TimeStamp    time.Time `gorm:"autoCreateTime"`
}
