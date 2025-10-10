package services

import (
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
		ProjectID:      int(data.ProjectID),
		IssueID:        int(data.IssueIID),
	}
}

// 创建一个Ticket(返回SourceRef、IdemoptencyKey和Error)
func (tk *TicketService) Create(data dto.TicketDTO) error {
	// 调用数据层进行创建
	ticketORM := tk.toORMData(data)
	return tk.DAO.Create(ticketORM)
}

// 不存在时创建记录，存在则更新 （并返回TicketID）
func (tk *TicketService) CreateOrUpdate(data dto.TicketDTO) (int64, error) {
	// 内建生成雪花ID
	data.UID = utils.GenerateSnowKey()

	condORM := tk.toORMData(dto.TicketDTO{
		SourceRef:      data.SourceRef,
		IdemoptencyKey: data.IdemoptencyKey,
	})
	dataORM := tk.toORMData(data)
	if !tk.DAO.IsExist(condORM) {
		// 创建
		return data.UID, tk.DAO.Create(dataORM)
	}
	return tk.DAO.Update(condORM, &dbo.Ticket{
		Status:    common.EditedStatus, // 修改为Edited状态
		ProjectID: int(data.ProjectID),
		IssueID:   int(data.IssueIID),
		AuthorID:  data.AuthorID,
	})
}

// 更新Ticket状态信息（会按照指定前置状态进行判断）
func (tk *TicketService) UpdateTicketStats(cond dto.TicketDTO, targetStats string, exceptStats ...string) error {
	// 更新Ticket信息
	condORM := tk.toORMData(cond)
	return tk.DAO.ValidateAndUpdate(condORM, &dbo.Ticket{
		Status: targetStats,
	}, exceptStats...)
}

// 查找获取Ticket唯一标识
func (tk *TicketService) GetSourceRef(cond dto.TicketDTO) string {
	// 更新Ticket信息
	condORM := tk.toORMData(cond)
	res, err := tk.DAO.FindOne(condORM)
	if err != nil {
		return ""
	}
	return res.SourceRef
}

// 统计每个状态的Ticket数量
func (tk *TicketService) StatusCount() (map[string]int, error) {
	return tk.DAO.StatsCount()
}

// 检查事件payload
//
//	type CheckEventV2 interface {
//		UpdateTicketStats(targetStats string, exceptStats ...string) error
//	}
type FristCheckEventV2 struct {
	// Tasker   TaskService
	Ref      string // SourceRef 或 BusinessRef
	Source   int
	TicketID int64
	UserID   uint
}

type DoubleCheckEventV2 struct {
	FristCheckEventV2
	FristCheck *core.PreCheckResultGroup
}
