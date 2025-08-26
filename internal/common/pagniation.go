package common

import (
	"sql_demo/internal/utils"
)

type Pagniation struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
	Offset     int `json:"offset"` // 计算偏移量
	// Data       []any `json:"data"`   // 当前页的数据
}

// 新建分页器，会按照Page和PageSize初始化Offset
func NewPaginatior(page, pageSize int) (Pagniation, error) {
	if page < 1 {
		return Pagniation{}, utils.GenerateError("PaginatiorErr", "Page must be >= 1")
	}
	if pageSize < 1 {
		return Pagniation{}, utils.GenerateError("PaginatiorErr", "PageSize must be >= 1")
	}
	return Pagniation{
		Page:     page,
		PageSize: pageSize,
		Offset:   (page - 1) * pageSize,
	}, nil
}

func (p *Pagniation) SetTotalPages(totalPages int) {
	p.TotalPages = totalPages
}

func (p *Pagniation) SetTotal(total int) {
	p.Total = total
}
