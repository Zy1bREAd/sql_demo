package services

import (
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
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
func (tk *TicketService) Create(data dto.TicketDTO) error {
	// 调用数据层进行创建
	ticketORM := tk.toORMData(data)
	return tk.DAO.Create(ticketORM)
}

// 不存在时创建记录，存在则更新 （根据SourceRef）
func (tk *TicketService) CreateOrUpdate(data dto.TicketDTO) error {
	// 调用数据层进行创建
	condORM := tk.toORMData(dto.TicketDTO{
		SourceRef:      data.SourceRef,
		IdemoptencyKey: data.IdemoptencyKey,
	})
	dataORM := tk.toORMData(data)
	return tk.DAO.CreateOrUpdate(condORM, dataORM)
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
	Tasker    TaskService
	SourceRef string
	Source    string
	TicketID  int64
	UserID    uint
}

type DoubleCheckEventV2 struct {
	FristCheckEventV2
	FristCheck *core.PreCheckResultGroup
}
