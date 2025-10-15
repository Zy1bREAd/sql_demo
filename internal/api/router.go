package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	_ "sql_demo/docs"
	dto "sql_demo/internal/api/dto"
	"sql_demo/internal/auth"
	api "sql_demo/internal/clients"
	glbapi "sql_demo/internal/clients/gitlab"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/services"
	"sql_demo/internal/utils"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
)

// 定义路由注册函数
type FnRegisterRoute func(rgPublic *gin.RouterGroup, rgAuth *gin.RouterGroup)

// 定义需要注册的路由列表
var fnRoutes []FnRegisterRoute

// 添加路由注册函数
func RegisterRoute(fn FnRegisterRoute) {
	// 如果注册函数为nil，则跳过；反之加入路由注册表中
	if fn == nil {
		log.Println("FnRegisterRoute 不需要注册")
		return
	}
	fnRoutes = append(fnRoutes, fn)
}

// 封装路由组件
func InitRouter() {
	// programatically set swagger info

	r := gin.New()
	r.Use(corsMiddleware())
	rgPublic := r.Group("/api/v1/public")
	rgAuth := r.Group("/api/v1/")
	// 使用认证鉴权中间件
	rgAuth.Use(authMiddleware())
	InitBaseRoutes()

	// Swagger API Docs
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.PersistAuthorization(true)))

	// 加载路由注册函数
	for _, fn := range fnRoutes {
		fn(rgPublic, rgAuth)
	}

	// 优雅关闭：监听信号量的context，等待信号量出现进行cancel()；传入gin server进行关闭。
	conf := conf.GetAppConf().GetBaseConfig()
	srv := &http.Server{
		// Addr:    address,
		Handler: r,
	}
	// 判断是否同时启动HTTP + HTTPS
	if conf.WebSrvEnv.TLSEnv.Enabled {
		srv.Addr = conf.WebSrvEnv.Addr + ":" + conf.WebSrvEnv.TLSEnv.Port
		go func() {
			fmt.Printf("Listening and serving HTTPS on %s\n", conf.WebSrvEnv.Addr+":"+conf.WebSrvEnv.TLSEnv.Port)
			srv.ListenAndServeTLS(conf.WebSrvEnv.TLSEnv.Cert, conf.WebSrvEnv.TLSEnv.Key)
		}()
		// 将HTTP重定向到HTTPS
		go func() {
			fmt.Printf("Listening and serving HTTP on %s\n", conf.WebSrvEnv.Addr+":"+conf.WebSrvEnv.Port)
			http.ListenAndServe(conf.WebSrvEnv.Addr+":"+conf.WebSrvEnv.Port, http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
				}))
		}()
	} else {
		go func() {
			fmt.Printf("Listening and serving HTTP on %s\n", conf.WebSrvEnv.Addr+":"+conf.WebSrvEnv.Port)
			srv.Addr = conf.WebSrvEnv.Addr + ":" + conf.WebSrvEnv.Port
			srv.ListenAndServe()
		}()
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan // 正因为需要这个阻塞情况（当读取到信号量即不阻塞代表要触发优雅关闭）

	// 等待连接处理完（等待超时）关闭即可shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		panic(utils.GenerateError("ShutDonwFailed", err.Error()))
	} else {
		utils.DebugPrint("ServerIsClosed", "Gin Server is closed,Bye Bye")
	}

}

// ! 初始化基础路由
func InitBaseRoutes() {
	RegisterRoute(func(rgPublic, rgAuth *gin.RouterGroup) {
		// 注册、登录认证
		// rgPublic.POST("/register", userCreate)
		// rgPublic.POST("/login", userLogin)
		rgPublic.POST("/sso/login", userSSOLogin)
		rgPublic.GET("/sso/callback", SSOCallBack)
		rgAuth.GET("/users/register", RegisterUsersByGitLab)

		// 结果展示、导出与下载
		rgAuth.GET("/result/temp-view/:identifier", getTicketTempResults)
		rgAuth.GET("/result/export", ResultExport)
		rgAuth.GET("/result/download", DownloadFile)

		// GitLab相关Webhook回调接口
		rgPublic.POST("/issue/callback", IssueCallBack)
		rgPublic.POST("/comment/callback", CommentCallBack)

		// API JSON格式请求专用路由
		rgAuth.POST("/sql-task/create", SQLTaskCreate)
		rgAuth.PUT("/sql-task/update", SQLTaskUpdate)
		rgAuth.DELETE("/sql-task/delete", SQLTaskDelete)
		rgAuth.POST("/sql-task/batch-delete", SQLTaskDelete)
		rgAuth.GET("/sql-task/list", SQLTaskList)
		rgAuth.POST("/sql-task/handle", SQLTaskHandle)

		rgAuth.GET("/pre-check/details", getPreCheckData)
		rgAuth.GET("/result/details", getTaskResultData)

		// 配置管理
		rgAuth.POST("/env/create", CreateEnvInfo)
		rgAuth.POST("/env/list", GetEnvConfigList)
		rgAuth.GET("/env/name/list", GetEnvNameList)
		rgAuth.PUT("/env/update/:uid", UpdateEnvInfo)
		rgAuth.DELETE("/env/delete/:uid", DeleteEnvInfo)

		rgAuth.POST("/sources/create", CreateDBInfo)
		rgAuth.POST("/sources/list", GetDBConfig)
		rgAuth.PUT("/sources/update/:uid", UpdateDBInfo)
		rgAuth.DELETE("/sources/delete/:uid", DeleteDBInfo)
		rgAuth.POST("/sources/connection/test", SourceConnTest)
		rgAuth.GET("/sources/search", SearchDBConfig)
		rgAuth.GET("/sources/health-check", HealthCheckSources)

		// 审计日志
		rgAuth.POST("/audit/record/list", GetAuditRecord)

		// 仪表盘
		rgAuth.GET("/console/dashborad", GetDashboradData)

		// ai chat
		rgAuth.GET("/chat", AiChat)
	})
}

// 跨域问题
func corsMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", "*")                                          //允许跨域请求的来源，这里指示前端地址。可以使用通配符*来放行全部
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE,OPTIONS")            //允许请求的方法，指明实际请求所允许使用的 HTTP 方法
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin,Accept,Content-Type, Authorization") // 允许的请求头字段，指明实际请求中允许携带的首部字段
		ctx.Writer.Header().Set("Access-Control-Max-Age", "3600")                                            // OPTION请求的缓存时间，单位为秒
		ctx.Writer.Header().Set("Access-Control-Expose-Headers", "Location")

		// 预处理OPTIONS
		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(200)
			return
		}

		ctx.Next()
	}
}

// 认证鉴权中间件
func authMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		reqToken := ctx.Request.Header.Get("Authorization")
		tokenList := strings.Split(reqToken, " ")
		if len(tokenList) != 2 || !strings.HasPrefix(tokenList[0], "Bearer") {
			// common.ErrorResp(ctx, "Jwt token not exist")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid,please check"})
			return
		}
		userClaim, err := utils.ParseJWT(tokenList[1])
		if err != nil {
			// common.ErrorResp(ctx, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		ctx.Set("user_id", userClaim.UserID)
		ctx.Set("user_email", userClaim.Email)
		ctx.Next()
	}
}

// User obj
type UserInfo struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// @Summary		创建SQL任务
// @Description	根据JSON内容创建SQL任务
// @Tags			SQLTask
// @Produce		json
// @Param			content	body		SQLTaskRequest	true	"SQL task content"
// @Success		200		{object}	common.JSONResponse{data=TicketResponse}
// @Failure		500		{object}	common.JSONResponse
// @Router			/sql-task/create [post]
// @Security		ApiKeyAuth
func SQLTaskCreate(ctx *gin.Context) {
	userIdStr := ctx.GetString("user_id")
	// 解析数据（需要临时存储）
	var content dto.SQLTaskRequest
	err := ctx.ShouldBindJSON(&content)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	err = content.Validate()
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}

	// 临时存储task信息
	apiTask := services.NewAPITaskService(services.WithAPITaskUserID(userIdStr))
	// 创建API Ticket
	tkData, err := apiTask.Create(content)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}

	// 返回sourceRef以及idempKey
	common.SuccessResp(ctx, dto.TicketResponse{
		SourceRef:      tkData.SourceRef,
		IdemoptencyKey: tkData.IdemoptencyKey,
		BusinessRef:    tkData.BusinessRef,
	}, "Create Ticket Success")
}

// @Summary		编辑更新SQLTask
// @Description	编辑更新SQLTask
// @Tags			SQLTask
// @Produce		json
// @Param			business_ref	query		string			true	"busniess ref"
// @Param			content			body		SQLTaskRequest	true	"sql task content"
// @Success		200				{object}	common.JSONResponse{data=TicketResponse}
// @Failure		500				{object}	common.JSONResponse
// @Router			/sql-task/update [put]
// @Security		ApiKeyAuth
func SQLTaskUpdate(ctx *gin.Context) {
	userIdStr := ctx.GetString("user_id")
	bussRefVal := ctx.Query("business_ref")
	if bussRefVal == "" {
		common.ErrorResp(ctx, "BussinessRef is not exist")
		return
	}
	// 解析数据（需要临时存储）
	var content dto.SQLTaskRequest
	err := ctx.ShouldBindJSON(&content)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	err = content.Validate()
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}

	// 临时存储task信息
	apiTask := services.NewAPITaskService(services.WithAPITaskUserID(userIdStr), services.WithAPITaskBusinessRef(bussRefVal))
	// 创建API Ticket
	err = apiTask.Update(content)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}

	// 返回sourceRef以及idempKey
	common.SuccessResp(ctx, dto.TicketResponse{
		BusinessRef: bussRefVal,
	}, "Update Ticket Success")
}

// @Summary		删除SQLTask
// @Description	删除SQLTask（可单删可批量）
// @Tags			SQLTask
// @Produce		json
// @Param			business_ref	query		string	true	"busniess ref"
// @Success		200				{object}	common.JSONResponse{data=TicketResponse}
// @Failure		500				{object}	common.JSONResponse
// @Router			/sql-task/delete [delete]
// @Router			/sql-task/delete [post]
// @Security		ApiKeyAuth
func SQLTaskDelete(ctx *gin.Context) {
	userIdStr := ctx.GetString("user_id")
	switch ctx.Request.Method {
	case "POST":
		fmt.Println("批量删除,暂不实现")
		// 返回sourceRef以及idempKey
		common.SuccessResp(ctx, nil, "批量删除,暂不实现")
	case "DELETE":
		bussRefVal := ctx.Query("business_ref")
		if bussRefVal == "" {
			common.ErrorResp(ctx, "BussinessRef is not exist")
			return
		}

		// 临时存储task信息
		apiTask := services.NewAPITaskService(services.WithAPITaskUserID(userIdStr), services.WithAPITaskBusinessRef(bussRefVal))
		// 创建API Ticket
		err := apiTask.Delete()
		if err != nil {
			common.ErrorResp(ctx, err.Error())
			return
		}
		// 返回sourceRef以及idempKey
		common.SuccessResp(ctx, dto.TicketResponse{
			BusinessRef: bussRefVal,
		}, "Delete Ticket Success")
	}
}

// @Summary		获取预检结果
// @Description	获取预检结果详情(通过bussinessRef)
// @Tags			SQLTask
// @Produce		json
// @Param			business_ref	query		string	true	"busniess ref"
// @Success		200				{object}	common.JSONResponse
// @Failure		500				{object}	common.JSONResponse
// @Router			/pre-check/details [get]
// @Security		ApiKeyAuth
func getPreCheckData(ctx *gin.Context) {
	bussRefVal := ctx.Query("business_ref")
	if bussRefVal == "" {
		common.ErrorResp(ctx, "BussinessRef is not exist")
		return
	}
	apiSrv := services.NewAPITaskService(services.WithAPITaskBusinessRef(bussRefVal))
	preCheckData, err := apiSrv.GetCheckData()
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	common.SuccessResp(ctx, preCheckData, "Get Success")
}

type SQLResultGroupDTO struct {
	*core.SQLResultGroupV2
}

// @Summary		获取任务数据集
// @Description	获取任务数据集详情
// @Tags			SQLTask
// @Produce		json
// @Param			business_ref	query		string	true	"busniess ref"
// @Success		200				{object}	common.JSONResponse{data=SQLResultGroupDTO}
// @Failure		500				{object}	common.JSONResponse
// @Router			/result/details [get]
// @Security		ApiKeyAuth
func getTaskResultData(ctx *gin.Context) {
	bussRefVal := ctx.Query("business_ref")
	if bussRefVal == "" {
		common.ErrorResp(ctx, "BussinessRef is not exist")
		return
	}
	// 获取UserId
	userID, err := getUserIDByJWT(ctx)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	apiSrv := services.NewAPITaskService(
		services.WithAPITaskBusinessRef(bussRefVal),
		services.WithAPITaskUserID(userID))
	taskResData, err := apiSrv.GetResultData()
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	common.SuccessResp(ctx, SQLResultGroupDTO{
		taskResData,
	}, "Get Result Success")
}

// 获取数据集(外链形式进行简单展示)
func getTaskResultDataURL(ctx *gin.Context) {
	bussRefVal := ctx.Query("business_ref")
	if bussRefVal == "" {
		common.ErrorResp(ctx, "BussinessRef is not exist")
		return
	}
	apiSrv := services.NewAPITaskService(services.WithAPITaskBusinessRef(bussRefVal))
	taskResData, err := apiSrv.GetResultData()
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	common.SuccessResp(ctx, taskResData, "Get Result Success")
}

// @Summary		处理SQLTask
// @Description	对SQLTask执行操作
// @Tags			SQLTask
// @Produce		json
// @Param			business_ref	query		string	true	"busniess ref"
// @Param			reason			query		string	false	"page size"
// @Param			action			query		int		true	"handle action flag"
// @Success		200				{object}	common.JSONResponse{data=SQLTaskResponse}
// @Failure		500				{object}	common.JSONResponse
// @Router			/sql-task/handle [post]
//
// @Security		ApiKeyAuth
func SQLTaskHandle(ctx *gin.Context) {
	userIdStr := ctx.GetString("user_id")
	// 解析数据（需要临时存储）
	var content dto.SQLTaskReview
	err := ctx.ShouldBindJSON(&content)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	err = content.Validate()
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}

	apiTask := services.NewAPITaskService(
		services.WithAPITaskUserID(userIdStr),
		services.WithAPITaskBusinessRef(content.BusinessRef),
	)
	err = apiTask.ActionHandle(ctx, content.Action)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}

	// 返回sourceRef以及idempKey
	common.SuccessResp(ctx, dto.SQLTaskResponse{
		BusinessRef: content.BusinessRef,
		Action:      common.ActionHandleMap[content.Action],
		Operator:    userIdStr,
		OperateTime: time.Now().Format("20060102150405"),
	}, "Handle Action Success")

}

// @Summary		获取任务列表
// @Description	获取任务列表(具备分页)
// @Tags			SQLTask
// @Produce		json
// @Param			page		query		int		false	"page number"
// @Param			page_size	query		int		false	"page size"
// @Param			status		query		string	false	"status of sql task"
// @Success		200			{object}	common.JSONResponse{data=TicketDTO}
// @Failure		500			{object}	common.JSONResponse
// @Router			/sql-task/handle [get]
//
// @Security		ApiKeyAuth
func SQLTaskList(ctx *gin.Context) {
	// pageQuery := ctx.Query("page")
	// pageSizeQuery := ctx.Query("page_size")
	// taskStatusQuery := ctx.Query("status")
	userIdStr := ctx.GetString("user_id")
	type RDTO struct {
		Page     int    `form:"page,default=1"`
		PageSize int    `form:"page_size,default=10"`
		Status   string `form:"status"`
	}
	var rdto RDTO
	err := ctx.ShouldBindQuery(&rdto)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}

	pagni, err := common.NewPaginatior(rdto.Page, rdto.PageSize)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}

	apiTask := services.NewAPITaskService(
		services.WithAPITaskUserID(userIdStr),
	)
	// TODO: 补充搜索条件
	result, err := apiTask.Get(dto.TicketDTO{
		Status: rdto.Status,
	}, &pagni)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni.SetTotalPages(int(pagni.Total+pagni.PageSize-1) / pagni.PageSize)
	common.SuccessResp(ctx, result, "Get Success", common.WithPagination(pagni))
}

func IssueCallBack(ctx *gin.Context) {
	err := services.PreCheckCallback(ctx, "Issue Hook")
	if err != nil {
		common.NotAuthResp(ctx, err.Error()) // ERROR：401
		return
	}
	//! callback 核心逻辑
	// 获取并解析请求体
	var reqBody services.IssueWebhook
	err = ctx.ShouldBind(&reqBody)
	if err != nil {
		common.ErrorResp(ctx, common.FormatPrint("BindError", err.Error()))
		return
	}
	err = reqBody.OpenIssueHandle()
	if err != nil {
		common.ErrorResp(ctx, common.FormatPrint("IssueHandleError", err.Error()))
		return
	}
	// common.Str2TimeObj(reqBody.ObjectAttr.CreateAt)
	common.SuccessResp(ctx, nil, "Success gitlab issue callback")
}

func CommentCallBack(ctx *gin.Context) {
	err := services.PreCheckCallback(ctx, "Note Hook")
	if err != nil {
		common.NotAuthResp(ctx, err.Error()) // ERROR：401
		return
	}
	// 评论事件触发的逻辑
	var reqBody services.CommentWebhook
	err = ctx.ShouldBind(&reqBody)
	if err != nil {
		common.ErrorResp(ctx, common.FormatPrint("BindError", err.Error()))
		return
	}
	err = reqBody.CommentIssueHandle()
	if err != nil {
		glab := glbapi.InitGitLabAPI()
		commentErr := glab.CommentCreate(glbapi.GitLabComment{
			ProjectID: reqBody.Project.ID,
			IssueIID:  reqBody.Issue.IID,
			Message:   err.Error(),
		})
		if commentErr != nil {
			common.ErrorResp(ctx, common.FormatPrint("CommnetError", err.Error()))
			return
		}
		common.ErrorResp(ctx, common.FormatPrint("CommentHandleError", err.Error()))
		return
	}
	common.SuccessResp(ctx, nil, "Success gitlab comment callback")
}

// 用户登录（鉴权）
// func userLogin(ctx *gin.Context) {
// 	var loginInfo UserInfo
// 	ctx.ShouldBind(&loginInfo)
// 	// 通过数据库验证
// 	user := dbo.User{
// 		Email: loginInfo.Email,
// 	}
// 	userInfo, err := user.BasicLogin(loginInfo.Password)
// 	if err != nil {
// 		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
// 		return
// 	}
// 	token, err := utils.GenerateJWT(userInfo.ID, userInfo.Name, userInfo.Email)
// 	if err != nil {
// 		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
// 	}
// 	common.SuccessResp(ctx, gin.H{
// 		"user_token": token,
// 		"user":       userInfo.Name,
// 	}, "user login success")
// }

// 处理gitlab SSO登录
func userSSOLogin(ctx *gin.Context) {
	oa2 := auth.GetOAuthConfig()
	state, err := auth.SetState()
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, utils.GenerateError("NoStateValue", err.Error()).Error())
		return
	}
	authURL := oa2.AuthCodeURL(state)
	log.Println("构造后的auth url:", authURL)
	// ctx.Redirect(http.StatusFound, authURL)
	// 构造authURL，由前端去跳转。
	common.SuccessResp(ctx, map[string]any{
		"redirect_url": authURL,
		"state":        state,
	}, "redirect to gitlab oauth")
}

// 身份提供商回调验证函数（用于Token置换）
func SSOCallBack(ctx *gin.Context) {
	// 防御CSRF攻击（确保请求state参数一致）
	reqState := ctx.Request.URL.Query().Get("state")
	if reqState == "" {
		common.DefaultResp(ctx, http.StatusBadRequest, nil, "Missing state parameter")
		return
	}
	_, exist := core.SessionMap.Get(reqState)
	if !exist {
		common.DefaultResp(ctx, http.StatusBadRequest, nil, "Invaild state parameter")
		return
	}
	// 清理缓存
	core.SessionMap.Del(reqState)

	// 获取授权码
	oa2 := auth.GetOAuthConfig()
	code := ctx.Request.URL.Query().Get("code")
	token, err := oa2.Exchange(context.Background(), code)
	if err != nil {
		common.ErrorResp(ctx, "Failed to exchange token:"+err.Error())
		return
	}

	// 通过获取身份提供商的token中的用户信息，构造我们application的token
	oauthConf := auth.GetOAuthConfig()
	client := oauthConf.Client(context.Background(), token)
	appConf := conf.GetAppConf().GetBaseConfig()
	resp, err := client.Get(appConf.SSOEnv.ClientAPI)
	if err != nil {
		common.ErrorResp(ctx, "Failed to get user info:"+err.Error())
		return
	}
	defer resp.Body.Close()

	var oauthUser auth.GitLabUser
	err = json.NewDecoder(resp.Body).Decode(&oauthUser)
	if err != nil {
		common.ErrorResp(ctx, "decode user info is failed, "+err.Error())
		return
	}
	// 完成数据库相关的逻辑
	var user dbo.User
	userId, err := user.SSOLogin(dbo.User{
		ID:       oauthUser.ID,
		Name:     oauthUser.Name,
		UserName: oauthUser.UserName,
		Email:    oauthUser.Email,
	})
	if err != nil {
		common.ErrorResp(ctx, "sso login failed, "+err.Error())
		return
	}
	// log.Println(gitlabUserInfo)
	appToken, err := utils.GenerateJWT(userId, oauthUser.Name, oauthUser.Email)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
	}
	common.SuccessResp(ctx, gin.H{
		"user_token": appToken,
		"user":       oauthUser.Name,
		"role":       "...",
	}, "sso login success")
}

// @Summary		导出结果集
// @Description	导出临时结果集成文件形式(SSE)
// @Tags			Result
// @Produce		json
// @Param			task_id		query		string	true	"task id"
// @Param			is_only		query		bool	true	"is only flag"
// @Param			result_idx	query		int		false	"only export index"
// @Success		200			{object}	[]byte
// @Failure		500			{object}	[]byte
// @Router			/result/export [get]
//
// @Security		ApiKeyAuth
func ResultExport(ctx *gin.Context) {
	//! 添加SSE的Header
	ctx.Header("Content-Type", "text/event-stream")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Connection", "keep-alive")

	userID, err := getUserIDByJWT(ctx)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	//! 解析URL上的query信息（手动解析，因为ShouldBind失效）
	var reqBody dto.ExportResultRequest
	ctx.ShouldBindQuery(&reqBody)
	queryVals := ctx.Request.URL.Query()
	taskIdVal := queryVals.Get("task_id")
	isOnlyVal := queryVals.Get("is_only")

	isOnlyBool, err := strconv.ParseBool(isOnlyVal)
	if err != nil {
		common.ErrorResp(ctx, "StrConvErr"+err.Error())
		return
	}

	if isOnlyBool {
		resultIdxVal := queryVals.Get("result_idx")
		idxInt64, err := strconv.ParseInt(resultIdxVal, 10, 32)
		if err != nil {
			common.ErrorResp(ctx, "resultIdx is invalid "+err.Error())
			return
		}
		reqBody.ResultIdx = int(idxInt64)
	}
	reqBody.TaskID = taskIdVal
	reqBody.IsOnly = isOnlyBool
	// 生产导出任务的事件
	exportSrv := services.NewExportResultService(
		services.WithExportIsOnly(isOnlyBool),
		services.WithExportTaskID(taskIdVal),
		services.WithExportUserID(utils.StrToUint(userID)), // TODO: 需要转换使用本应用中的UserID
		services.WithExportResultIndex(reqBody.ResultIdx),
	)
	// 生产【导出结果集】事件
	notifyChannel, err := exportSrv.Prepare()
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	defer close(notifyChannel)

	// 指定超时时间内，等待【导出结果集】事件的消费完成...
	timeCtx, cancel := context.WithTimeout(ctx, common.DefaultCacheMapDDL*time.Second)
	defer cancel()

	// 清理资源
	select {
	case details := <-notifyChannel:
		if details.Errrr != nil {
			// 此时SSE连接已开，必须返回错误消息和关闭sse
			sseContent := utils.SSEEvent{
				ID:    2,
				Event: "error",
				Data:  details.Errrr.Error(),
			}
			utils.SSEMsgOnSend(ctx, &sseContent)
			// 发送完毕关闭连接
			sseContent = utils.SSEEvent{
				ID:    4,
				Event: "closed",
				Data:  "",
			}
			utils.SSEMsgOnSend(ctx, &sseContent)
			return
		}
		// 发送初始化连接消息
		sseContent := utils.SSEEvent{
			ID:    1,
			Event: "connected",
			Data:  "OK",
		}
		utils.SSEMsgOnSend(ctx, &sseContent)
		// TODO: 生成签名的URL下载链接

		downloadURL := fmt.Sprintf("/result/download?task_id=%s", details.TaskID)
		// JSON序列化下载信息
		downloadInfo := map[string]string{
			"link":      downloadURL,
			"file_name": details.FileName,
		}
		bytesData, err := json.Marshal(&downloadInfo)
		if err != nil {
			sseContent = utils.SSEEvent{
				ID:    2,
				Event: "json_error",
				Data:  err.Error(),
			}
			utils.SSEMsgOnSend(ctx, &sseContent)
		}

		sseContent = utils.SSEEvent{
			ID:    0,
			Event: "download_ready",
			Data:  string(bytesData),
		}
		utils.SSEMsgOnSend(ctx, &sseContent)
		utils.DebugPrint("ExportSuccess", downloadURL+" is Exported.")

		defer func() {
			// 发送完毕关闭连接
			sseContent := utils.SSEEvent{
				ID:    4,
				Event: "closed",
				Data:  "",
			}
			utils.SSEMsgOnSend(ctx, &sseContent)
		}()
		return
	case <-timeCtx.Done():
		utils.ErrorPrint("SSETimeOut", "SSE Connection is timeout")
		return
	}
}

// @Summary		下载导出结果文件
// @Description	下载导出结果集文件
// @Tags			Result
// @Produce		json
// @Param			task_id	query		string	true	"task id"
// @Success		200		{object}	[]byte
// @Failure		500		{object}	[]byte
// @Router			/result/download [get]
//
// @Security		ApiKeyAuth
func DownloadFile(ctx *gin.Context) {
	//TODO: 引入其他参数防止伪造task_id来请求偷取下载文件
	taskId := ctx.Query("task_id")
	if taskId == "" {
		common.DefaultResp(ctx, common.RespFailed, nil, "URL query taskid is invalid")
		return
	}
	// 获取 UserId
	userIDStr, err := getUserIDByJWT(ctx)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
	}

	downloadSrv := services.NewDownloadService(utils.StrToUint(userIDStr))
	filePath, err := downloadSrv.Download(taskId)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	//! 设置下载文件的响应信息
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filePath))
	ctx.File(filePath)
}

// @Summary		输出临时结果集
// @Description	外链形式展示ticket任务执行结果
// @Tags			Result
// @Produce		json
// @Param			identifier	query		string	true	"identifier (uukey)"
// @Success		200			{object}	common.JSONResponse{data=TempResultResponse}
// @Failure		500			{object}	common.JSONResponse
// @Router			/result/temp-view/:identifier [get]
//
// @Security		ApiKeyAuth
func getTicketTempResults(ctx *gin.Context) {
	uuKey := ctx.Param("identifier")
	// 获取UserId
	userID, err := getUserIDByJWT(ctx)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	// 获取临时数据集
	tempResSrv := services.NewTempResultService(utils.StrToUint(userID))
	data, err := tempResSrv.GetData(ctx, dto.TempResultDTO{
		UUKey: uuKey,
	}, true)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	if tempResSrv.IsExpried() {
		common.DefaultResp(ctx, common.RespFailed, nil, "Result Data is Expired")
		return
	}

	// 同步：日志审计记录
	auditLogSrv := services.NewAuditRecordService()
	auditLogSrv.Update(dto.AuditRecordDTO{
		TaskID:    data.GID,
		EventType: "SQL_QUERY",
	}, "RESULT_VIEW", tempResSrv.Operator, "")
	common.SuccessResp(ctx, dto.TempResultResponse{
		Data:      data.Data,
		TaskID:    data.GID,
		IsExport:  tempResSrv.IsExport(),
		IsExpried: tempResSrv.IsExpried(),
	}, "Get Temp Data Success")
}

// 用于手动将GitLab User注册进来User
func RegisterUsersByGitLab(ctx *gin.Context) {
	// 校验管理员操作
	val, exist := ctx.Get("user_id")
	if !exist {
		common.DefaultResp(ctx, common.IllegalRequest, nil, "User is not exist")
		return
	}
	userID, ok := val.(uint)
	if !ok {
		common.DefaultResp(ctx, common.RespFailed, nil, "UserId type is incrroect")
		return
	}
	validUser := dbo.User{
		ID: userID,
	}
	if !validUser.IsAdminUser() {
		common.DefaultResp(ctx, common.NoPermissionRequest, nil, "the user is no permission")
		return
	}
	api := glbapi.InitGitLabAPI()
	users, err := api.UserList()
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	for _, gu := range users {
		// 跳过不活跃的用户
		if gu.State != "active" {
			continue
		}
		var u dbo.User
		dbConn := dbo.HaveSelfDB().GetConn()
		res := dbConn.Where("git_lab_identity = ?", gu.ID).First(&u)
		if res.Error != nil {
			// 不存在即创建用户
			if errors.Is(err, gorm.ErrRecordNotFound) {
				u := dbo.User{
					Name:           gu.Name,
					UserName:       gu.Username,
					GitLabIdentity: gu.ID,
					Email:          gu.Email,
					UserType:       dbo.GITLABUSER,
				}
				dbConn.Create(&u)
				continue
			}
		}
		// 存在即更新
		err = dbConn.Model(&u).Updates(dbo.User{
			ID:             u.ID,
			Name:           gu.Name,
			UserName:       gu.Username,
			GitLabIdentity: gu.ID,
			Email:          gu.Email,
			UserType:       2,
		}).Error
		if err != nil {
			utils.DebugPrint("UpdateGitLabUser", "update gitlab user is failed")
			continue
		}
	}
	common.SuccessResp(ctx, users, "success")
}

// 创建数据库连接信息
func CreateDBInfo(ctx *gin.Context) {
	var dbInfo dto.QueryDataBaseDTO
	err := ctx.ShouldBindJSON(&dbInfo)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	// 表单校验
	portInt, err := strconv.ParseInt(dbInfo.Connection.Port, 10, 64)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, utils.GenerateError("ValidateErr", err.Error()).Error())
		return
	}
	if portInt <= 0 || portInt > 65535 {
		common.DefaultResp(ctx, common.RespFailed, nil, utils.GenerateError("ValidateErr", "Port Range is 0 to 65535").Error())
		return
	}
	pwdLength := len(dbInfo.Connection.Password)
	if pwdLength < 6 && pwdLength > 16 {
		common.DefaultResp(ctx, common.RespFailed, nil, utils.GenerateError("ValidateErr", "Password Length is 6 to 16").Error())
		return
	}
	// 默认值
	if dbInfo.Connection.Port == "" {
		dbInfo.Connection.Port = "3306"
	}
	if dbInfo.Connection.User == "" {
		dbInfo.Connection.User = "root"
	}
	source := services.NewSourceService()
	err = source.Create(dbInfo)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, nil, "create success")
}

// Create or update API information request | 创建或更新API信息
type QueryEnvSwagger struct {
	IsWrite bool     `json:"is_write"`
	Name    string   `json:"name"`
	Tag     []string `json:"tag"`
	Desc    string   `json:"description"`
}

// 创建数据库连接信息
//
//	@Summary		Create a Env Info
//	@Description	创建数据库环境信息
//	@Security		ApiKeyAuth
//	@Tags			Env
//	@Accept			application/json
//	@Produce		application/json
//	@Param			env_body	body		QueryEnvDTO	true	"Env Body"
//	@Success		200			{object}	common.JSONResponse{data=nil}
//	@Failure		500			{object}	common.JSONResponse
//	@Router			/env/create [post]
func CreateEnvInfo(ctx *gin.Context) {
	var envInfo dto.QueryEnvDTO
	err := ctx.ShouldBindJSON(&envInfo)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	// 表单校验
	if envInfo.Name == "" {
		common.DefaultResp(ctx, common.RespFailed, nil, utils.GenerateError("ValidateError", "data is not null").Error())
		return
	}
	if len(envInfo.Name) < 2 || len(envInfo.Name) > 16 {
		common.DefaultResp(ctx, common.RespFailed, nil, utils.GenerateError("ValidateError", "data length should be 2 to 16").Error())
		return
	}
	srv := services.NewEnvService()
	err = srv.Create(envInfo)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, nil, "create success")
}

// 获取全部数据源信息
func GetDBConfig(ctx *gin.Context) {
	// RDTO: Request DTO ,主要接收前端的请求体数据，将其反序列化
	type RDTO struct {
		Page     int `json:"page"`
		PageSize int `json:"page_size"`
		// Data     QueryEnvDTO `json:"conds"`
	}
	var rdto RDTO
	err := ctx.ShouldBindJSON(&rdto)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni, err := common.NewPaginatior(rdto.Page, rdto.PageSize)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	var sourceDTO dto.QueryDataBaseDTO
	source := services.NewSourceService()
	result, err := source.Get(sourceDTO, &pagni)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni.SetTotalPages(int(pagni.Total+pagni.PageSize-1) / pagni.PageSize)
	common.SuccessResp(ctx, result, "get db all data success", common.WithPagination(pagni))
}

// 健康检查-数据源(alphe)
func HealthCheckSources(ctx *gin.Context) {
	pool := dbo.GetDBPoolManager()
	type HealthCheck struct {
		Env     string `json:"env_name"`
		Service string `json:"service"`
		Status  int    `json:"status"`
		Msg     string `json:"msg"`
	}
	result := make([]HealthCheck, 0)
	for env, services := range pool.Pool {
		for srv, dbIst := range services {
			if dbIst == nil {
				continue
			}
			result = append(result, HealthCheck{
				Env:     env,
				Service: srv,
				Status:  dbIst.StatusCode,
				Msg:     dbIst.Errrr,
			})
		}
	}
	common.SuccessResp(ctx, result, "ok")
}

// 获取全部数据源信息
func SearchDBConfig(ctx *gin.Context) {
	// 依靠URL上的Params作为参数
	kw := ctx.Query("keyword")
	page := ctx.Query("page")
	pageSize := ctx.Query("page_size")
	pageInt, err := strconv.ParseInt(page, 10, 64)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pageSizeInt, err := strconv.ParseInt(pageSize, 10, 64)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni, err := common.NewPaginatior(int(pageInt), int(pageSizeInt))
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	source := services.NewSourceService()
	result, err := source.FilterKeyWord(kw, &pagni)
	// result, err := source.GetorSearch(kw, &pagni)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni.SetTotalPages(int(pagni.Total+pagni.PageSize-1) / pagni.PageSize)
	common.SuccessResp(ctx, result, "search db configs success", common.WithPagination(pagni))
}

func SourceConnTest(ctx *gin.Context) {
	var connInfo dbo.ConnectInfo
	ctx.ShouldBindJSON(&connInfo)
	err := dbo.TestDBIstConn(connInfo)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, "ConnectError: "+err.Error())
		return
	}
	common.SuccessResp(ctx, "OK", "source connection is OK")
}

// 仅获取Env名字的函数
func GetEnvNameList(ctx *gin.Context) {
	env := services.NewEnvService()
	result := env.NameListWithPool()
	common.SuccessResp(ctx, result, "get env name list success")
}

// 获取全部Env信息
func GetEnvConfigList(ctx *gin.Context) {
	// RDTO: Request DTO ,主要接收前端的请求体数据，将其反序列化
	type RDTO struct {
		Page     int             `json:"page"`
		PageSize int             `json:"page_size"`
		Data     dto.QueryEnvDTO `json:"conds"`
	}
	var rdto RDTO
	err := ctx.ShouldBindJSON(&rdto)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni, err := common.NewPaginatior(rdto.Page, rdto.PageSize)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}

	env := services.NewEnvService()
	result, err := env.Get(rdto.Data, &pagni)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni.SetTotalPages(int(pagni.Total+pagni.PageSize-1) / pagni.PageSize)
	common.SuccessResp(ctx, result, "get env data success", common.WithPagination(pagni))
}

func UpdateEnvInfo(ctx *gin.Context) {
	uid := ctx.Param("uid")
	if uid == "" {
		common.DefaultResp(ctx, common.RespFailed, nil, "Invalid UID")
		return
	}
	// 解析用户要更新的数据体
	var envInfo dto.QueryEnvDTO
	err := ctx.ShouldBindJSON(&envInfo)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, "request body is error: "+err.Error())
		return
	}
	envInfo.UID = uid
	env := services.NewEnvService()
	result := env.UpdateInfo(dto.QueryEnvDTO{
		UID: uid,
	}, envInfo)
	common.SuccessResp(ctx, result, "update env Success")
}

func UpdateDBInfo(ctx *gin.Context) {
	uid := ctx.Param("uid")
	if uid == "" {
		common.DefaultResp(ctx, common.RespFailed, nil, "Invalid UID")
		return
	}
	// 解析用户数据体
	var envInfo dto.QueryDataBaseDTO
	err := ctx.ShouldBindJSON(&envInfo)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, "request body is error: "+err.Error())
		return
	}
	if envInfo.ConfirmedPassword == "" || envInfo.Connection.Password == "" {
		common.DefaultResp(ctx, common.RespFailed, nil, "Password Item is cannot be null")
		return
	}
	envInfo.UID = uid
	source := services.NewSourceService()
	err = source.Update(dto.QueryDataBaseDTO{
		UID: uid,
	}, envInfo)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, nil, "update db config success")
}

func DeleteEnvInfo(ctx *gin.Context) {
	uid := ctx.Param("uid")
	if uid == "" {
		common.DefaultResp(ctx, common.RespFailed, nil, "Invalid  UID")
		return
	}
	// 解析用户要更新的数据体
	var envInfo dto.QueryEnvDTO
	envInfo.UID = uid
	env := services.NewEnvService()
	result := env.Delete(envInfo)
	common.SuccessResp(ctx, result, "delete env Success")
}

func DeleteDBInfo(ctx *gin.Context) {
	uid := ctx.Param("uid")
	if uid == "" {
		common.DefaultResp(ctx, common.RespFailed, nil, "Invalid UID")
		return
	}
	source := services.NewSourceService()
	err := source.Delete(dto.QueryDataBaseDTO{
		UID: uid,
	})
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, "request body is error: "+err.Error())
		return
	}
	common.SuccessResp(ctx, nil, "delete db config success")
}

// 审计日志
func GetAuditRecord(ctx *gin.Context) {
	// RDTO: Request DTO ,主要接收前端的请求体数据，将其反序列化
	type RDTO struct {
		Page     int                `json:"page"`
		PageSize int                `json:"page_size"`
		Data     dto.AuditRecordDTO `json:"conds"`
	}
	var rdto RDTO
	err := ctx.ShouldBindJSON(&rdto)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni, err := common.NewPaginatior(rdto.Page, rdto.PageSize)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	audit := services.NewAuditRecordService()
	results, err := audit.Get(dto.AuditRecordDTO{}, &pagni)

	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni.SetTotalPages(int(pagni.Total+pagni.PageSize-1) / pagni.PageSize)
	common.SuccessResp(ctx, results, "ok", common.WithPagination(pagni))
}

// 仪表盘数据
func GetDashboradData(ctx *gin.Context) {
	var ticket dto.TicketStatusStatsDTO
	res, err := ticket.StatsCount()
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, res, "ok", common.WithPagination(common.Pagniation{
		Total: len(res),
	}))
}

func AiChat(ctx *gin.Context) {
	client, err := api.NewAIClient()
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	res, err := client.NewChat(ctx, "您好，你怎么知道我是不是人工智能？请简短回答核心")
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, res.JSONResult(), "ok")
}

// ! 抽象获取UserID的函数
func getUserIDByJWT(ctx *gin.Context) (string, error) {
	val, exist := ctx.Get("user_id")
	if !exist {
		return "", utils.GenerateError("NoPermission", "The User is Not Exist")
	}
	userIDVal, ok := val.(string)
	if !ok {
		return "", utils.GenerateError("NoPermission", "Convert UserID Type is Failed")
	}
	return userIDVal, nil
}
