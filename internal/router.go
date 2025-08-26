package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	api "sql_demo/api/gitlab"
	"sql_demo/internal/auth"
	"sql_demo/internal/common"
	"sql_demo/internal/conf"
	"sql_demo/internal/core"
	dbo "sql_demo/internal/db"
	"sql_demo/internal/event"
	"sql_demo/internal/utils"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
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
	r := gin.New()
	r.Use(corsMiddleware())
	rgPublic := r.Group("/api/v1/public")
	rgAuth := r.Group("/api/v1/")
	// 使用认证鉴权中间件
	rgAuth.Use(authMiddleware())
	InitBaseRoutes()

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
		rgAuth.GET("/result/temp-view/:identifier", showTempQueryResult)
		rgAuth.GET("/result/export", ResultExport)
		rgAuth.GET("/result/download", DownloadFile)

		// GitLab相关Webhook回调接口
		rgPublic.POST("/issue/callback", IssueCallBack)
		rgPublic.POST("/comment/callback", CommentCallBack)

		// JSON格式请求专用路由
		rgAuth.POST("/sql/excute", SQLExcuteTest)

		// 配置管理
		rgAuth.POST("/env/create", CreateEnvInfo)
		rgAuth.GET("/env/list", GetEnvConfigList)
		rgAuth.PUT("/env/update/:uid", UpdateEnvInfo)
		rgAuth.DELETE("/env/delete/:uid", DeleteEnvInfo)

		rgAuth.POST("/sources/create", CreateDBInfo)
		rgAuth.GET("/sources/list", GetDBConfigList)
		rgAuth.PUT("/sources/update/:uid", UpdateDBInfo)
		rgAuth.DELETE("/sources/delete/:uid", DeleteDBInfo)

		// 审计日志
		rgAuth.POST("/audit/record/list", GetAuditRecord)

		// 仪表盘
		rgAuth.GET("/console/dashborad", GetDashboradData)
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

// func userCreate(ctx *gin.Context) {
// 	var userInfo UserInfo
// 	ctx.ShouldBind(&userInfo)
// 	user := dbo.User{
// 		Name:     userInfo.Name,
// 		Password: userInfo.Password,
// 		Email:    userInfo.Email,
// 	}
// 	err := user.Create()
// 	if err != nil {
// 		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
// 	}
// 	// 返回创建信息
// 	common.SuccessResp(ctx, "token=...", "Get resultMap all keys success")
// }

func SQLExcuteTest(ctx *gin.Context) {
	fmt.Printf("处理用户请求，%s\n", time.Now().String())
	val, exist := ctx.Get("user_id")
	if !exist {
		common.ErrorResp(ctx, "User not exist")
		return
	}
	usrIdStr, ok := val.(string)
	if !ok {
		common.ErrorResp(ctx, "convert type is failed")
		return
	}
	var content api.SQLIssueTemplate
	err := ctx.ShouldBindJSON(&content)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	fmt.Printf("完成请求信息搜集，%s\n", time.Now().String())

	gid := utils.GenerateUUIDKey()
	qtg := &core.QTaskGroup{
		GID:      gid,
		StmtRaw:  content.Statement,
		UserID:   utils.StrToUint(usrIdStr),
		DBName:   content.DBName,
		Env:      content.Env,
		Service:  content.Service,
		IsExport: content.IsExport,
		Deadline: content.Deadline * 5,
	}
	// 事件驱动：封装成Event推送到事件通道(v2.0)
	ep := event.GetEventProducer()
	ep.Produce(event.Event{
		Type:    "sql_query",
		Payload: qtg,
	})
	fmt.Printf("生产SQL查询消息的事件，%s\n", time.Now().String())

	// 同步等待获取结果
	<-core.TestCh
	fmt.Printf("完成SQL查询的消费事件，%s\n", time.Now().String())
	res, exist := core.ResultMap.Get(qtg.GID)
	if !exist {
		common.ErrorResp(ctx, "Not found result")
		return
	}
	if result, ok := res.(*dbo.SQLResultGroup); ok {
		if result.Errrr != nil {
			common.ErrorResp(ctx, result.Errrr.Error())
			return
		}
		common.SuccessResp(ctx, result.ResGroup, "sql query excute is success")
		fmt.Printf("响应数据，%s\n", time.Now().String())
		return
	}
	common.ErrorResp(ctx, "result is null")
	fmt.Printf("响应数据，%s\n", time.Now().String())
}

func IssueCallBack(ctx *gin.Context) {
	err := api.PreCheckCallback(ctx, "Issue Hook")
	if err != nil {
		common.NotAuthResp(ctx, err.Error()) // ERROR：401
		return
	}
	//! callback 核心逻辑
	// 获取并解析请求体
	var reqBody api.IssueWebhook
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
	err := api.PreCheckCallback(ctx, "Note Hook")
	if err != nil {
		common.NotAuthResp(ctx, err.Error()) // ERROR：401
		return
	}
	// 评论事件触发的逻辑
	var reqBody api.CommentWebhook
	err = ctx.ShouldBind(&reqBody)
	if err != nil {
		common.ErrorResp(ctx, common.FormatPrint("BindError", err.Error()))
		return
	}
	err = reqBody.CommentIssueHandle()
	if err != nil {
		glab := api.InitGitLabAPI()
		commentErr := glab.CommentCreate(reqBody.Project.ID, reqBody.Issue.IID, err.Error())
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

// 结果集导出路由逻辑(SSE)
func ResultExport(ctx *gin.Context) {
	// 添加SSE的Header
	ctx.Header("Content-Type", "text/event-stream")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Connection", "keep-alive")

	val, exist := ctx.Get("user_id")
	if !exist {
		common.ErrorResp(ctx, "User not exist")
		return
	}
	idStr, ok := val.(string)
	if !ok {
		common.ErrorResp(ctx, "UserId type is incrroect")
		return
	}
	// 解析URL上的query信息（手动解析，因为ShouldBind失效）
	var t core.ExportTask
	// err := ctx.ShouldBindWith(&t, binding.Query)
	queryVals := ctx.Request.URL.Query()
	taskIdVal := queryVals.Get("task_id")
	isOnlyVal := queryVals.Get("is_only")

	t.GID = taskIdVal
	isOnlyBool, err := strconv.ParseBool(isOnlyVal)
	if err != nil {
		utils.DebugPrint("StrConvErr", err.Error())
	}
	if t.GID == "" {
		common.ErrorResp(ctx, "TaskID is invalid "+err.Error())
		return
	}
	if isOnlyBool {
		resultIdxVal := queryVals.Get("result_idx")
		idxInt64, err := strconv.ParseInt(resultIdxVal, 10, 32)
		t.ResultIdx = int(idxInt64)
		if err != nil {
			common.ErrorResp(ctx, "resultIdx is invalid "+err.Error())
			return
		}
	}
	t.UserID = utils.StrToUint(idStr)
	t.IsOnly = isOnlyBool
	t.Submit()
	common.SuccessResp(ctx, nil, "export task is start working....")

	// 设置超时控制
	timeCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	if err := t.GetResult(); err != nil {
		common.ErrorResp(ctx, "Export Result is Null "+err.Error())
		return
	}
	if t.Result == nil {
		common.ErrorResp(ctx, "Export Result is Null "+err.Error())
		return
	}
	select {
	case <-t.Result.Done:
		if t.Result.Error != nil {
			// 此时SSE连接已开，必须返回错误消息和关闭sse
			sseContent := utils.SSEEvent{
				ID:    2,
				Event: "error",
				Data:  t.Result.Error.Error(),
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
		// 生成签名的URL下载链接
		// uri := GenerateSignedURI(taskId)
		downloadURL := fmt.Sprintf("/result/download?task_id=%s", t.GID)
		// JSON序列化下载信息
		downloadInfo := map[string]string{
			"link":      downloadURL,
			"file_name": t.FileName,
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

func DownloadFile(ctx *gin.Context) {
	//! 引入其他参数防止伪造task_id来请求偷取下载文件
	taskId := ctx.Query("task_id")
	if taskId == "" {
		common.DefaultResp(ctx, common.RespFailed, nil, "URL query taskid is invalid")
		return
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()
	auditChan := make(chan struct{}, 1)
	// 插入记录V2
	go func() {
		// 获取UserId
		val, exist := ctx.Get("user_id")
		if !exist {
			common.ErrorResp(ctx, "User not exist")
			return
		}
		userId, ok := val.(string)
		if !ok {
			common.ErrorResp(ctx, "convert type is failed")
			return
		}
		// 获取Issue详情(使用taskId和UserId来查找对应的issue)
		var auditRecord dbo.AuditRecordV2
		dbConn := dbo.HaveSelfDB().GetConn()
		res := dbConn.Where("task_id = ?", taskId).First(&auditRecord)
		if res.Error != nil {
			cancel()
			utils.ErrorPrint("DBAPIError", res.Error.Error())
			return
		}
		if res.RowsAffected != 1 {
			cancel()
			utils.ErrorPrint("DBAPIError", "rows is zero")
			return
		}
		// 日志审计插入v2
		auditRecord.ID = 0
		auditRecord.UserID = utils.StrToUint(userId)
		auditRecord.CreateAt = time.Now()

		err := auditRecord.InsertOne("RESULT_DOWNLOAD")
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
		}
		auditChan <- struct{}{}
	}()
	if !dbo.AllowResultExport(taskId) {
		common.DefaultResp(ctx, common.RespFailed, nil, "result file is not allow to export")
		return
	}
	// 获取文件路径并下载
	mapVal, exist := core.ExportWorkMap.Get(taskId)
	if !exist {
		common.DefaultResp(ctx, common.RecordNotExist, nil, "export result is not exist,may be cleaned")
		return
	}
	exportResult, ok := mapVal.(*core.ExportResult)
	if !ok {
		common.DefaultResp(ctx, common.RecordNotExist, nil, "result file type not match")
		return
	}
	if _, err := os.Stat(exportResult.FilePath); err != nil {
		fmt.Println("file error:", err.Error())
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Result File is not exist"})
		return
	}
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", exportResult.FilePath))
	ctx.File(exportResult.FilePath)
	// 等待审计记录的完成
	select {
	case <-timeoutCtx.Done():
		common.ErrorResp(ctx, "handle timeout")
		return
	case <-auditChan:
		return
	}
}

// 外链形式展示ticket任务执行结果
func showTempQueryResult(ctx *gin.Context) {
	uuKey := ctx.Param("identifier")
	// 校验链接是否过期
	dbRes, err := dbo.GetTempResult(uuKey)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	// 插入审计日志的超时控制
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*25)
	defer cancel()
	auditChan := make(chan struct{}, 1)
	// 插入记录V2
	go func() {
		// 获取UserId
		val, exist := ctx.Get("user_id")
		if !exist {
			common.ErrorResp(ctx, "User not exist")
			return
		}
		userId, ok := val.(string)
		if !ok {
			common.ErrorResp(ctx, "convert type is failed")
			return
		}
		// 获取Issue详情(使用taskId和UserId来查找对应的issue)
		var auditRecord dbo.AuditRecordV2
		dbConn := dbo.HaveSelfDB().GetConn()
		res := dbConn.Where("task_id = ?", dbRes.TaskId).First(&auditRecord)
		if res.Error != nil {
			cancel()
			utils.ErrorPrint("DBAPIError", res.Error.Error())
			return
		}
		if res.RowsAffected != 1 {
			cancel()
			utils.ErrorPrint("DBAPIError", "rows is zero")
			return
		}
		// 日志审计插入v2
		auditRecord.ID = 0
		auditRecord.UserID = utils.StrToUint(userId)
		auditRecord.CreateAt = time.Now()

		err := auditRecord.InsertOne("RESULT_VIEW")
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
		}
		auditChan <- struct{}{}
	}()
	// 结果集是否存在
	userResult, exist := core.ResultMap.Get(dbRes.TaskId)
	if !exist {
		common.DefaultResp(ctx, common.RespFailed, nil, "SQL Query result is not exist")
		return
	}
	if val, ok := userResult.(*dbo.SQLResultGroup); ok {
		common.SuccessResp(ctx, gin.H{
			"result":    val.ResGroup,
			"is_export": dbRes.IsAllowExport,
			"task_id":   val.GID,
		}, "SUCCESS")
	}
	// 等待审计记录的完成
	select {
	case <-timeoutCtx.Done():
		common.ErrorResp(ctx, "handle timeout")
		return
	case <-auditChan:
		return
	}
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
	api := api.InitGitLabAPI()
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
	var dbInfo core.QueryDataBaseDTO
	err := ctx.ShouldBindJSON(&dbInfo)
	if err != nil {
		common.DefaultResp(ctx, 555, nil, err.Error())
		return
	}
	err = dbInfo.Create()
	if err != nil {
		common.DefaultResp(ctx, 555, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, nil, "create success")
}

// 创建数据库连接信息
func CreateEnvInfo(ctx *gin.Context) {
	var envInfo core.QueryEnvDTO
	err := ctx.ShouldBindJSON(&envInfo)
	if err != nil {
		common.DefaultResp(ctx, 555, nil, err.Error())
		return
	}
	err = envInfo.Create()
	if err != nil {
		common.DefaultResp(ctx, 555, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, nil, "create success")
}

// 获取全部数据源信息
func GetDBConfigList(ctx *gin.Context) {
	var env core.QueryEnvDTO
	result, err := env.GetDBList(nil)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, result, "get db all data success")
}

// 获取全部Env信息
func GetEnvConfigList(ctx *gin.Context) {
	var env core.QueryEnvDTO
	result, err := env.GetAllData()
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, result, "get env data success")
}

func UpdateEnvInfo(ctx *gin.Context) {
	uid := ctx.Param("uid")
	if uid == "" {
		common.DefaultResp(ctx, 555, nil, "Invalid UID")
		return
	}
	// 解析用户要更新的数据体
	var envInfo core.QueryEnvDTO
	err := ctx.ShouldBindJSON(&envInfo)
	if err != nil {
		common.DefaultResp(ctx, 555, nil, "request body is error: "+err.Error())
		return
	}
	envInfo.UID = uid
	result := envInfo.UpdateEnvInfo()
	common.SuccessResp(ctx, result, "update env Success")
}

func UpdateDBInfo(ctx *gin.Context) {
	uid := ctx.Param("uid")
	if uid == "" {
		common.DefaultResp(ctx, 555, nil, "Invalid UID")
		return
	}
	// 解析用户数据体
	var envInfo core.QueryDataBaseDTO
	err := ctx.ShouldBindJSON(&envInfo)
	if err != nil {
		common.DefaultResp(ctx, 555, nil, "request body is error: "+err.Error())
		return
	}
	envInfo.UID = uid
	err = envInfo.UpdateDBInfo()
	if err != nil {
		common.DefaultResp(ctx, 555, nil, "request body is error: "+err.Error())
		return
	}
	common.SuccessResp(ctx, nil, "update db config success")
}

func DeleteEnvInfo(ctx *gin.Context) {
	uid := ctx.Param("uid")
	if uid == "" {
		common.DefaultResp(ctx, 555, nil, "Invalid  UID")
		return
	}
	// 解析用户要更新的数据体
	var envInfo core.QueryEnvDTO
	envInfo.UID = uid
	result := envInfo.DeleteEnvInfo()
	common.SuccessResp(ctx, result, "delete env Success")
}

func DeleteDBInfo(ctx *gin.Context) {
	uid := ctx.Param("uid")
	if uid == "" {
		common.DefaultResp(ctx, 555, nil, "Invalid UID")
		return
	}
	var envInfo core.QueryDataBaseDTO
	envInfo.UID = uid
	err := envInfo.DeleteDBInfo()
	if err != nil {
		common.DefaultResp(ctx, 555, nil, "request body is error: "+err.Error())
		return
	}
	common.SuccessResp(ctx, nil, "delete db config success")
}

// 审计日志
func GetAuditRecord(ctx *gin.Context) {
	// RDTO: Request DTO ,主要接收前端的请求体数据，将其反序列化
	type RDTO struct {
		Page     int                 `json:"page"`
		PageSize int                 `json:"page_size"`
		Data     core.AuditRecordDTO `json:"conds"`
	}
	var dto RDTO
	err := ctx.ShouldBindJSON(&dto)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni, err := common.NewPaginatior(dto.Page, dto.PageSize)
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	results, err := dto.Data.Get(&pagni)

	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	pagni.SetTotalPages(int(pagni.Total+pagni.PageSize-1) / pagni.PageSize)
	common.SuccessResp(ctx, results, "ok", common.WithPagination(pagni))
}

// 仪表盘数据
func GetDashboradData(ctx *gin.Context) {
	var ticket core.TicketStatusStatsDTO
	res, err := ticket.StatsCount()
	if err != nil {
		common.DefaultResp(ctx, common.RespFailed, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, res, "ok", common.WithPagination(common.Pagniation{
		Total: len(res),
	}))
}
