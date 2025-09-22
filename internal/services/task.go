package services

import (
	"context"
	"fmt"
	"slices"
	dto "sql_demo/internal/api/dto"
	glbapi "sql_demo/internal/clients/gitlab"
	"sql_demo/internal/common"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
)

type Task struct {
}

type TaskService interface {
	FristCheck(context.Context, *core.PreCheckResultGroup) error
}

type Option func(*APITaskService)

// API调用
type APITaskService struct {
	SourceRef string
	UID       int64
	UserID    uint
}

func NewAPITaskService(opts ...Option) *APITaskService {
	apiTask := &APITaskService{}
	for _, opt := range opts {
		opt(apiTask)
	}
	return apiTask
}

func WithUserID(userID string) Option {
	return func(as *APITaskService) {
		as.UserID = utils.StrToUint(userID)
	}
}

func WithSourceRef(sourceRef string) Option {
	return func(as *APITaskService) {
		as.SourceRef = sourceRef
	}
}

// API调用创建SQLTask和Ticket
func (srv *APITaskService) Create(data dto.SQLTaskRequest) (*dto.TicketDTO, error) {
	// 创建Ticket(需要根据客户端来主动构造business_ref)
	tk := NewTicketService()
	ticketDTO, err := tk.Create(srv.UserID, "normal")
	if err != nil {
		return nil, err
	}
	// 临时存储
	core.APITaskBodyMap.Set(srv.UID, data, common.DefaultCacheMapDDL, common.APITaskBodyMapCleanFlag)

	// 生产事件(预检阶段)
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "sql_check",
		Payload: &core.FristCheckEvent{
			TicketID:  ticketDTO.UID,
			UserID:    srv.UserID,
			SourceRef: ticketDTO.SourceRef,
		},
	})

	return ticketDTO, nil
}

func (srv *APITaskService) FristCheck(ctx context.Context, resultGroup *core.PreCheckResultGroup) error {
	preCheckRes := &core.PreCheckResultGroup{
		Data: &core.PreCheckResult{
			ParsedSQL:       make([]core.SQLForParseV2, 0),
			ExplainAnalysis: make([]core.ExplainAnalysisResult, 0),
			Soar: core.SoarCheck{
				Results: make([]byte, 0),
			},
		},
	}
	// 获取Task Body数据
	body, exist := core.APITaskBodyMap.Get(srv.UID)
	if !exist {
		return utils.GenerateError("TaskBodyError", "API Task Body is not exist")
	}
	taskBodyVal, ok := body.(dto.SQLTaskRequest)
	if !ok {
		return utils.GenerateError("TaskBodyError", "API Task Body Type is not match")
	}

	// 更新Ticket信息(正在处理预检)
	targetStats := []string{
		common.CreatedStatus,
		common.EditedStatus,
		common.ReInitedStatus,
	}
	tk := NewTicketService()
	err := tk.UpdateTicketStats(dbo.Ticket{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.PreCheckingStatus, targetStats...)
	if err != nil {
		return err
	}

	// 解析SQL
	parseStmts, err := core.ParseV3(ctx, taskBodyVal.Statement)
	if err != nil {
		return err
	}
	preCheckRes.Data.ParsedSQL = parseStmts

	// EXPLAIN 解析与建议
	for _, stmt := range parseStmts {
		analysisRes, err := stmt.ExplainAnalysis(ctx,
			taskBodyVal.Env,
			taskBodyVal.DBName,
			taskBodyVal.Service,
			core.AnalysisFnOpts{
				WithExplain: true,
				WithDDL:     true,
				WithSchema:  true,
				WithAi:      true,
			},
		)
		if err != nil {
			return err
		}
		preCheckRes.Data.ExplainAnalysis = append(preCheckRes.Data.ExplainAnalysis, *analysisRes)

	}

	// SOAR 分析（利用系统层面SOAR操作实现，捕获屏幕输出流）
	if taskBodyVal.IsSOAR {
		soar := core.NewSoarAnalyzer(
			core.WithReportFormat("json"),
			core.WithSQLContent(taskBodyVal.Statement),
			core.WithCommandPath("/opt"),
			core.WithCommand("soar.linux-amd64_v11"),
		)
		soarResult, err := soar.Analysis()
		if err != nil {
			return err
		}
		preCheckRes.Data.Soar.Results = soarResult
	}

	// !自定义规则解析
	ist, err := dbo.HaveDBIst(taskBodyVal.Env, taskBodyVal.DBName, taskBodyVal.Service)
	if err != nil {
		return err
	}
	// 1. 检查黑名单（数据库和数据表）
	dbPool := dbo.GetDBPoolManager()
	illegalDBs := dbPool.ExcludeDBList()
	illegalTables := ist.ExcludeTableList()
	recuErrCh := make(chan error, 1)
	// 递归版
	var recu func([]core.FromParse)
	for _, stmt := range parseStmts {
		stmtVal := stmt //! 避免闭包循环引用问题
		recu = func(froms []core.FromParse) {
			// goroutine 资源控制
			select {
			case <-ctx.Done():
				recuErrCh <- utils.GenerateError("GoroutineError", "Goroutine Break Off")
				return
			default:
			}

			for _, f := range froms {
				// 需要处理派生表的情况（subFrom出现违规表)
				if slices.Contains(illegalDBs, f.DBName) {
					recuErrCh <- utils.GenerateError("IllegalTable", fmt.Sprintf("%s SQL DB Name is illegal.Statement: `%s`", f.DBName, stmt.SafeStmt))
					return
				}
				if slices.Contains(illegalTables, f.TableName) {
					recuErrCh <- utils.GenerateError("IllegalTable", fmt.Sprintf("%s SQL Table Name is illegal.Statement: `%s`", f.TableName, stmt.SafeStmt))
					return
				}
				if f.IsDerivedTable {
					recu(f.SubFrom)
				}

				// 2. 检查是否可写
				if !ist.IsWrite && stmtVal.Action != "select" {
					recuErrCh <- utils.GenerateError("NoPermission", "Your DB Instance is no permission")
					return
				}
			}
		}
		recu(stmtVal.From)
	}
	if err := <-recuErrCh; err != nil {
		return err
	}

	// 更新Ticket信息
	err = tk.UpdateTicketStats(dbo.Ticket{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.PreCheckSuccessStatus, common.PreCheckingStatus)
	if err != nil {
		return err
	}

	//  最终赋值
	resultGroup = preCheckRes
	return nil
}

// GitLab 调用
type GitLabTaskService struct {
	SourceRef string
	UID       int64
	UserID    uint
}

func NewGitLabTaskService(opts ...Option) *GitLabTaskService {
	gitlabTask := &GitLabTaskService{}
	return gitlabTask
}

func (srv *GitLabTaskService) FristCheck(ctx context.Context, resultGroup *core.PreCheckResultGroup) error {
	preCheckRes := &core.PreCheckResultGroup{
		Data: &core.PreCheckResult{
			ParsedSQL:       make([]core.SQLForParseV2, 0),
			ExplainAnalysis: make([]core.ExplainAnalysisResult, 0),
			Soar: core.SoarCheck{
				Results: make([]byte, 0),
			},
		},
	}
	// 获取Task Body数据(GItlab)
	val, exist := core.GitLabIssueMap.Get(srv.UID)
	if !exist {
		return utils.GenerateError("GitLabIssueNotExist", "Issue Cache is not exist")

	}
	issCache, ok := val.(*IssueCache)
	if !ok {
		return utils.GenerateError("GitLabIssueInvalid", "Issue Cache type is invalid")

	}

	// 更新Ticket信息(正在处理预检)
	targetStats := []string{
		common.CreatedStatus,
		common.EditedStatus,
		common.ReInitedStatus,
	}
	tk := NewTicketService()
	err := tk.UpdateTicketStats(dbo.Ticket{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.PreCheckingStatus, targetStats...)
	if err != nil {
		return err

	}

	// 解析SQL
	parseStmts, err := core.ParseV3(ctx, issCache.Content.Statement)
	if err != nil {
		return err
	}
	preCheckRes.Data.ParsedSQL = parseStmts

	// EXPLAIN 解析与建议
	glab := glbapi.InitGitLabAPI()
	for _, stmt := range parseStmts {
		analysisRes, err := stmt.ExplainAnalysis(ctx,
			issCache.Content.Env,
			issCache.Content.DBName,
			issCache.Content.Service,
			core.AnalysisFnOpts{
				WithExplain: true,
				WithDDL:     true,
				WithSchema:  true,
				WithAi:      true,
			},
		)
		if err != nil {
			return err
		}
		preCheckRes.Data.ExplainAnalysis = append(preCheckRes.Data.ExplainAnalysis, *analysisRes)
		// 输出到gitlab中
		err = glab.CommentCreate(glbapi.GitLabComment{
			ProjectID: issCache.ProjectID,
			IssueIID:  issCache.IID,
			Message:   analysisRes.AiAnalysis,
		})
		if err != nil {
			fmt.Println(err.Error())
		}
	}

	// TODO：SOAR 分析（利用系统层面SOAR操作实现，捕获屏幕输出流）
	if issCache.Content.IsSoarAnalysis {
		soar := core.NewSoarAnalyzer(
			core.WithReportFormat("json"),
			core.WithSQLContent(issCache.Content.Statement),
			core.WithCommandPath("/opt"),
			core.WithCommand("soar.linux-amd64_v11"),
		)
		soarResult, err := soar.Analysis()
		if err != nil {
			return err
		}
		preCheckRes.Data.Soar.Results = soarResult
	}

	// !自定义规则解析
	ist, err := dbo.HaveDBIst(issCache.Content.Env, issCache.Content.DBName, issCache.Content.Service)
	if err != nil {
		return err
	}
	// 1. 检查黑名单（数据库和数据表）
	dbPool := dbo.GetDBPoolManager()
	illegalDBs := dbPool.ExcludeDBList()
	illegalTables := ist.ExcludeTableList()
	recuErrCh := make(chan error, 1)
	// 递归版
	var recu func([]core.FromParse)
	for _, stmt := range parseStmts {
		stmtVal := stmt //! 避免闭包循环引用问题
		recu = func(froms []core.FromParse) {
			// goroutine 资源控制
			select {
			case <-ctx.Done():
				recuErrCh <- utils.GenerateError("GoroutineError", "Goroutine Break Off")
				return
			default:
			}

			for _, f := range froms {
				// 需要处理派生表的情况（subFrom出现违规表)
				if slices.Contains(illegalDBs, f.DBName) {
					recuErrCh <- utils.GenerateError("IllegalTable", fmt.Sprintf("%s SQL DB Name is illegal.Statement: `%s`", f.DBName, stmt.SafeStmt))
					return
				}
				if slices.Contains(illegalTables, f.TableName) {
					recuErrCh <- utils.GenerateError("IllegalTable", fmt.Sprintf("%s SQL Table Name is illegal.Statement: `%s`", f.TableName, stmt.SafeStmt))
					return
				}
				if f.IsDerivedTable {
					recu(f.SubFrom)
				}

				// 2. 检查是否可写
				if !ist.IsWrite && stmtVal.Action != "select" {
					recuErrCh <- utils.GenerateError("NoPermission", "Your DB Instance is no permission")
					return
				}
			}
		}
		recu(stmtVal.From)
	}
	if err := <-recuErrCh; err != nil {
		return err
	}

	// 更新Ticket信息
	err = tk.UpdateTicketStats(dbo.Ticket{
		UID:      srv.UID,
		AuthorID: srv.UserID,
	}, common.PreCheckSuccessStatus, common.PreCheckingStatus)
	if err != nil {
		return err
	}

	// 最终赋值
	resultGroup = preCheckRes
	return nil
}
