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
	// 创建Ticket(需要根据客户端来主动构造business_ref)信息
	tk := NewTicketService()
	busniessDomain := "sql-task"
	snowKey := utils.GenerateSnowKey()
	shortUUID := utils.GenerateUUIDKey()[:4]
	userID := srv.UserID
	// {业务域}:user:{主体id}:{Source}:{雪花id}
	businessRef := fmt.Sprintf("%s:user:%d:%s:%d", busniessDomain, userID, "normal", snowKey)
	// {动作}:{雪花id}:{短UUID}
	IdempKey := fmt.Sprintf("%s:%d:%s", "submit", snowKey, shortUUID)

	dtoData := dto.TicketDTO{
		UID:            snowKey,
		Status:         common.CreatedStatus,
		Source:         "normal",
		SourceRef:      businessRef,
		IdemoptencyKey: IdempKey,
		AuthorID:       userID,
	}
	err := tk.Create(dtoData)
	if err != nil {
		return nil, err
	}
	// 临时存储
	core.APITaskBodyMap.Set(dtoData.UID, data, common.DefaultCacheMapDDL, common.APITaskBodyMapCleanFlag)

	// 生产事件(预检阶段)
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "sql_check",
		Payload: &FristCheckEventV2{
			TicketID:  dtoData.UID,
			UserID:    userID,
			SourceRef: dtoData.SourceRef,
			Tasker:    srv,
		},
	})

	return &dtoData, nil
}

func (srv *APITaskService) FristCheck(ctx context.Context, resultGroup *core.PreCheckResultGroup) error {
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
	resultGroup.Data.ParsedSQL = parseStmts

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
		resultGroup.Data.ExplainAnalysis = append(resultGroup.Data.ExplainAnalysis, *analysisRes)

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
		resultGroup.Data.Soar.Results = soarResult
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

	return nil
}

// GitLab 调用
type GitLabTaskService struct {
	SourceRef string
	UID       int64
	IssueIID  int
	ProjectID int
	UserID    uint
}

func NewGitLabTaskService(opts ...Option) *GitLabTaskService {
	gitlabTask := &GitLabTaskService{}
	return gitlabTask
}

// GitLab调用创建SQLTask和Ticket
func (srv *GitLabTaskService) Create(payload *IssuePayload) (*dto.TicketDTO, error) {
	// 获取用户真实ID
	user := dbo.User{
		GitLabIdentity: payload.Issue.AuthorID,
	}
	userID := user.GetGitLabUserId()
	// 创建Ticket(需要根据客户端来主动构造business_ref)信息
	tk := NewTicketService()
	busniessDomain := "sql-task"
	snowKey := utils.GenerateSnowKey()
	// {业务域}:user:{主体id}:{来源}:{项目ID}:{议题IID}
	businessRef := fmt.Sprintf("%s:user:%d:%s:%d:%d", busniessDomain, userID, "gitlab", payload.Issue.ProjectID, payload.Issue.IID)
	// {动作}:{项目ID}:{议题IID}
	IdempKey := businessRef

	tkData := dto.TicketDTO{
		UID:            snowKey,
		Status:         common.CreatedStatus,
		SourceRef:      businessRef,
		IdemoptencyKey: IdempKey,
		AuthorID:       userID,
		ProjectID:      payload.Issue.ProjectID,
		IssueIID:       payload.Issue.IID,
		Source:         "gitlab",
	}
	err := tk.CreateOrUpdate(tkData)
	if err != nil {
		return nil, err
	}
	// 缓存issue信息，若找不到则从数据库中查找。
	issCache := &IssueCache{
		Content: payload.Desc,
		Issue:   payload.Issue,
	}
	core.GitLabIssueMap.Set(tkData.UID, issCache, common.TicketCacheMapDDL, common.IssueTicketType)

	// 生产事件(预检阶段)
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type: "sql_check",
		Payload: &FristCheckEventV2{
			TicketID:  tkData.UID,
			UserID:    userID,
			SourceRef: tkData.SourceRef,
			Tasker:    srv,
		},
	})

	return &tkData, nil
}

func (srv *GitLabTaskService) FristCheck(ctx context.Context, resultGroup *core.PreCheckResultGroup) error {
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
	resultGroup.Data.ParsedSQL = parseStmts

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
		resultGroup.Data.ExplainAnalysis = append(resultGroup.Data.ExplainAnalysis, *analysisRes)
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
		resultGroup.Data.Soar.Results = soarResult
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

	return nil
}
