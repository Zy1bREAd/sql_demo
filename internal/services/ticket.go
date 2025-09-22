package services

import (
	"fmt"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/common"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/utils"
)

// Ticket
type TicketService struct {
	DAO dbo.Ticket // 数据crud
}

func NewTicketService() *TicketService {
	return &TicketService{
		DAO: dbo.Ticket{},
	}
}

func (tk *TicketService) toORMData(data dto.TicketDTO) *dbo.Ticket {
	return &dbo.Ticket{
		UID:            data.UID,
		Status:         data.Status,
		Source:         data.Source,
		SourceRef:      data.SourceRef,
		IdemoptencyKey: data.IdemoptencyKey,
		AuthorID:       data.AuthorID,
	}
}

// 创建一个Ticket(返回SourceRef、IdemoptencyKey和Error)
func (tk *TicketService) Create(userID uint, source string) (*dto.TicketDTO, error) {
	// userID := utils.StrToUint(userIDStr)
	// 创建Ticket(需要根据客户端来主动构造business_ref)
	shortUUID := utils.GenerateUUIDKey()[:4]
	busniessDomain := "sql-review"
	snowKey := utils.GenerateSnowKey()

	// {业务域}:user:{主体id}:{Source}:{雪花id}
	businessRef := fmt.Sprintf("%s:user:%d:normal:%d", busniessDomain, userID, snowKey)

	// {动作}:{雪花id}:{短UUID}
	IdempKey := fmt.Sprintf("%s:%d:%s", "submit", snowKey, shortUUID)
	if source == "" {
		source = "normal"
	}
	dtoData := dto.TicketDTO{
		UID:            snowKey,
		Status:         common.CreatedStatus,
		Source:         source,
		SourceRef:      businessRef,
		IdemoptencyKey: IdempKey,
		AuthorID:       userID,
	}
	ticketORM := tk.toORMData(dtoData)
	err := ticketORM.Create()
	if err != nil {
		return nil, err
	}

	return &dtoData, nil
}

// 更新Ticket状态信息，并按照指定前置状态进行判断
func (tk *TicketService) UpdateTicketStats(cond dbo.Ticket, targetStats string, exceptStats ...string) error {
	// 更新Ticket信息
	return tk.DAO.ValidateAndUpdateStatus(cond, targetStats, exceptStats...)
}

// 统计每个状态的Ticket数量
func (tk *TicketService) StatusCount() (map[string]int, error) {
	return tk.DAO.StatsCount()
}

// 检查事件payload
type CheckEventV2 interface {
	UpdateTicketStats(targetStats string, exceptStats ...string) error
}
type FristCheckEventV2 struct {
	Task      TaskService
	SourceRef string
	Source    string
	TicketID  int64
	UserID    uint
}

type DoubleCheckEventV2 struct {
	FristCheckEventV2
	FristCheck *core.PreCheckResultGroup
}
