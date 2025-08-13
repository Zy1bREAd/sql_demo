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
	rgAuth.Use(AuthMiddleware())
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
		rgPublic.POST("/register", userCreate)
		// rgPublic.POST("/login", userLogin)
		rgPublic.POST("/sso/login", userSSOLogin)
		rgPublic.GET("/sso/callback", SSOCallBack)

		// 导出文件下载
		rgAuth.GET("/result/export", ResultExport)
		rgAuth.GET("/result/download", DownloadFile)

		rgAuth.GET("/record/list", getUserAuditRecordHandler)

		rgAuth.GET("/:taskId/result", getQueryResult)
		rgAuth.GET("/sql/result/keys", getMapKeys)
		rgAuth.GET("/db/list", DBList)

		rgAuth.GET("/result/temp-view/:identifier", showTempQueryResult)
		rgPublic.GET("/gitlab/users", UpdateGitLabUsers)

		rgPublic.POST("/issue/callback", IssueCallBack)
		rgPublic.POST("/comment/callback", CommentCallBack)
		// 测试专用路由
		rgAuth.POST("/sql/excute", SQLExcuteTest)

		rgAuth.POST("/env/create", CreateEnvInfo)
		rgAuth.GET("/env/list", QueryEnvInfo)
		rgAuth.PUT("/env/update/:uid", UpdateEnvInfo)
		rgAuth.DELETE("/env/delete/:uid", DeleteEnvInfo)

		rgAuth.POST("/sources/create", CreateDBInfo)
		rgAuth.PUT("/sources/update/:uid", UpdateDBInfo)
		rgAuth.DELETE("/sources/delete/:uid", DeleteDBInfo)
	})
}

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
	//！ callback 核心逻辑
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

type UserQuery struct {
	Database  string `json:"db_name"`
	Statement string `json:"query_sql"`
	TaskID    string `json:"task_id"` // 任务ID
	UserID    string `json:"user_id"`
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
func AuthMiddleware() gin.HandlerFunc {
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

func DBList(ctx *gin.Context) {
	// 获取环境变量
	_, exist := ctx.Params.Get("env")
	if !exist {
		common.DefaultResp(ctx, 11, nil, "Env Name is not exist")
		return
	}
	// pool := dbo.newDBPoolManager()
	common.SuccessResp(ctx, nil, "get db list success")
}

// /api/v1/query
// func UserSQLQuery(ctx *gin.Context) {
// 	// 防止伪造jwt请求
// 	userID, exist := ctx.Get("user_id")
// 	if !exist {
// 		common.ErrorResp(ctx, "User not exist")
// 		return
// 	}
// 	var q UserQuery
// 	ctx.ShouldBind(&q)
// 	log.Println(q)

// 	// SQL语法解析并校验（v2.0)  - 格式化SQL查询语句（确保规范化）
// 	sqlRaw, err := ParseSQL(q.Statement, "select")
// 	if err != nil {
// 		common.DefaultResp(ctx, 1, nil, err.Error())
// 		return
// 	}
// 	// 提交异步任务入队(v1.0)
// 	// taskID := SubmitSQLTask(sqlRaw, q.Database, userID.(string))

// 	// 事件驱动：封装成Event推送到事件通道(v2.0)
// 	task := CreateSQLQueryTask(sqlRaw, q.Database, userID.(string))
// 	ep := GetEventProducer()
// 	ep.Produce(Event{
// 		Type:    "sql_query",
// 		Payload: task,
// 	})
// 	common.SuccessResp(ctx, map[string]string{
// 		"task_id": task.ID,
// 	}, "submit sql_query event success")
// }

// 通过SSE返回结果数据 ？?
func getQueryResult(ctx *gin.Context) {
	taskID := ctx.Param("taskId")
	if taskID == "" {
		common.ErrorResp(ctx, "taskID is null")
		return
	}
	userResult, exist := core.ResultMap.Get(taskID)
	// 仅获取不到key的时候重新获取
	if !exist {
		common.DefaultResp(ctx, -1, nil, "SQL查询中.......")
		return
	}
	if val, ok := userResult.(*dbo.SQLResult); ok {
		if val.Errrrr != nil {
			common.DefaultResp(ctx, 1, "", val.Errrrr.Error())
			return
		}
		common.SuccessResp(ctx, gin.H{
			"result":     val.Results,
			"rows_count": val.RowCount,
			"query_time": val.QueryTime,
		}, "SUCCESS")
	}

}

func getMapKeys(ctx *gin.Context) {
	userResult := core.ResultMap.Keys()
	log.Println(userResult)
	common.SuccessResp(ctx, userResult, "Get resultMap all keys success")
}

// User obj
type UserInfo struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func userCreate(ctx *gin.Context) {
	var userInfo UserInfo
	ctx.ShouldBind(&userInfo)
	user := dbo.User{
		Name:     userInfo.Name,
		Password: userInfo.Password,
		Email:    userInfo.Email,
	}
	err := user.Create()
	if err != nil {
		common.DefaultResp(ctx, 1, nil, err.Error())
	}
	// 返回创建信息
	common.SuccessResp(ctx, "token=...", "Get resultMap all keys success")
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
// 		common.DefaultResp(ctx, 1, nil, err.Error())
// 		return
// 	}
// 	token, err := utils.GenerateJWT(userInfo.ID, userInfo.Name, userInfo.Email)
// 	if err != nil {
// 		common.DefaultResp(ctx, 1, nil, err.Error())
// 	}
// 	common.SuccessResp(ctx, gin.H{
// 		"user_token": token,
// 		"user":       userInfo.Name,
// 	}, "user login success")
// }

func getQueryRecords(ctx *gin.Context) {
	err := dbo.AllAuditRecords()
	if err != nil {
		common.DefaultResp(ctx, 1, nil, err.Error())
		return
	}
	common.SuccessResp(ctx, "test ok", "Get query result success")
}

// 处理gitlab SSO登录
func userSSOLogin(ctx *gin.Context) {
	oa2 := auth.GetOAuthConfig()
	state, err := auth.SetState()
	if err != nil {
		common.DefaultResp(ctx, 1, nil, utils.GenerateError("NoStateValue", err.Error()).Error())
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
	// log.Println("resp body>>>", resp.Body)
	// 定义gitlab user info结构体用于获取数据
	var gitlabUserInfo struct {
		ID    uint   `json:"id"`
		Name  string `json:"username"`
		Email string `json:"email"`
	}
	err = json.NewDecoder(resp.Body).Decode(&gitlabUserInfo)
	if err != nil {
		common.ErrorResp(ctx, "decode user info is failed, "+err.Error())
		return
	}
	// 完成数据库相关的逻辑
	user := dbo.User{
		Name:  gitlabUserInfo.Name,
		Email: gitlabUserInfo.Email,
	}
	userId, err := user.SSOLogin()
	if err != nil {
		common.ErrorResp(ctx, "sso login failed, "+err.Error())
		return
	}
	// log.Println(gitlabUserInfo)
	appToken, err := utils.GenerateJWT(userId, gitlabUserInfo.Name, gitlabUserInfo.Email)
	if err != nil {
		common.DefaultResp(ctx, 1, nil, err.Error())
	}
	common.SuccessResp(ctx, gin.H{
		"user_token": appToken,
		"user":       gitlabUserInfo.Name,
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
		auditRecord.CreatAt = time.Now()

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

// // SSE处理，用于导出文件
// func SSEHandle(ctx *gin.Context) {
// 	ctx.Header("Content-Type", "text/event-stream")
// 	ctx.Header("Cache-Control", "no-cache")
// 	ctx.Header("Connection", "keep-alive")

// 	_, exist := ctx.Get("user_id")
// 	if !exist {
// 		common.ErrorResp(ctx, "User not exist")
// 		return
// 	}
// 	// 从URL Parma中获取taskId，查询导出任务的进度
// 	taskId := ctx.Query("task_id")
// 	if taskId == "" {
// 		log.Println("[TaskError] taskId is null,Abort!!!")
// 		return
// 	}

// 	// SSE处理逻辑超时控制
// 	timeoutCtx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
// 	defer cancel()
// 	// 获取对应taskId的<导出对象>信息
// 	mapVal, exist := core.ExportWorkMap.Get(taskId)
// 	if !exist {
// 		log.Println("[NotExist] export result not exist,exit(1)")
// 		return
// 	}
// 	exportJob, ok := mapVal.(*core.ExportResult)
// 	if !ok {
// 		log.Println("[TypeNotMatch] export result type is not match,exit(1)")
// 		return
// 	}
// 	for {
// 		select {
// 		// 等待通知export结束
// 		case <-exportJob.Done:
// 			// 判断是否有错误
// 			if exportJob.Error != nil {
// 				log.Println("[ExportFailed] export task is failed ==>", exportJob.Error.Error())
// 				// 此时SSE连接已开，必须返回错误消息和关闭sse
// 				sseContent := sseEvent{
// 					ID:    2,
// 					Event: "error",
// 					Data:  exportJob.Error.Error(),
// 				}
// 				SSEMsgOnSend(ctx, &sseContent)
// 				// 发送完毕关闭连接
// 				sseContent = sseEvent{
// 					ID:    4,
// 					Event: "closed",
// 					Data:  "",
// 				}
// 				SSEMsgOnSend(ctx, &sseContent)
// 				return
// 			}
// 			log.Println("[Completed] export task done")
// 			// 发送初始化连接确认(discard)

// 			// 生成签名的URL下载链接
// 			// uri := GenerateSignedURI(taskId)
// 			downloadURL := fmt.Sprintf("/result/download?task_id=%s", taskId)
// 			sseContent := sseEvent{
// 				ID:    0,
// 				Event: "download_ready",
// 				Data:  downloadURL,
// 			}
// 			SSEMsgOnSend(ctx, &sseContent)

// 			// 发送完毕关闭连接
// 			sseContent = sseEvent{
// 				ID:    4,
// 				Event: "closed",
// 				Data:  "",
// 			}
// 			SSEMsgOnSend(ctx, &sseContent)
// 			return
// 		case <-timeoutCtx.Done():
// 			log.Println("[TimeOut] sse handle timeout,exit 1")
// 			return
// 		default:
// 			log.Println("[Wait] waiting export task done")
// 			time.Sleep(time.Second * 2)
// 		}
// 	}

// }

// 获取指定用户的日志审计
func getUserAuditRecordHandler(ctx *gin.Context) {
	val, exist := ctx.Get("user_id")
	if !exist {
		common.ErrorResp(ctx, "server parse user is failed")
		return
	}
	userId, ok := val.(string)
	if !ok {
		common.ErrorResp(ctx, "convert type is failed")
		return
	}
	recordData, err := dbo.GetAuditRecordByUserID(userId)
	if err != nil {
		common.ErrorResp(ctx, err.Error())
		return
	}
	common.SuccessResp(ctx, recordData, "get audit records by userid")
}

// 外链形式展示ticket任务执行结果
func showTempQueryResult(ctx *gin.Context) {
	uuKey := ctx.Param("identifier")
	// 校验链接是否过期
	dbRes, err := dbo.GetTempResult(uuKey)
	if err != nil {
		common.DefaultResp(ctx, 1, nil, err.Error())
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
		auditRecord.CreatAt = time.Now()

		err := auditRecord.InsertOne("RESULT_VIEW")
		if err != nil {
			utils.ErrorPrint("AuditRecordV2", err.Error())
		}
		auditChan <- struct{}{}
	}()
	// 结果集是否存在
	userResult, exist := core.ResultMap.Get(dbRes.TaskId)
	if !exist {
		common.DefaultResp(ctx, 1, nil, "SQL Query result is not exist")
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

func UpdateGitLabUsers(ctx *gin.Context) {
	api := api.InitGitLabAPI()
	users, err := api.UserList()
	if err != nil {
		common.DefaultResp(ctx, 1, nil, err.Error())
		return
	}
	for _, gu := range users {
		if gu.State != "active" {
			continue
		}
		var u dbo.User
		dbConn := dbo.HaveSelfDB().GetConn()
		err := dbConn.Where("git_lab_identity = ?", gu.ID).First(&u).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				// 如果该用户不存在，则新建用户
				u := dbo.User{
					Name:           gu.Name,
					UserName:       gu.Username,
					GitLabIdentity: gu.ID,
					Email:          gu.Email,
					UserType:       2,
				}
				dbConn.Create(&u)
				continue
			}
		}
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
	common.SuccessResp(ctx, users, "get users")
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

// 获取全部Env信息
func QueryEnvInfo(ctx *gin.Context) {
	_, exist := ctx.GetQuery("env")
	if !exist {
		common.DefaultResp(ctx, 555, nil, "EnvKey is not exist")
		return
	}
	result := core.AllEnvInfo()
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
