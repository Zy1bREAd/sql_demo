package apis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

// 定义一个SSE消息内容对象
type sseEvent struct {
	ID    int    `json:"event_id"` // 0=download ready; 1=frist connected; 2=failed; 4=close connected;
	Event string `json:"event"`
	Data  string `json:"data"`
}

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

	// r.Run("localhost:21899")
	// 优雅关闭：监听信号量的context，等待信号量出现进行cancel()；传入gin server进行关闭。
	conf := GetAppConfig()
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
			// if err != nil {
			// 	panic(err)
			// }
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
		GenerateError("ShutDown Server Failed", err.Error())
	} else {
		log.Println("closed server!!")
	}

}

// 初始化基础路由
func InitBaseRoutes() {
	RegisterRoute(func(rgPublic, rgAuth *gin.RouterGroup) {
		rgPublic.POST("/register", userCreate)
		rgPublic.POST("/login", userLogin)
		rgPublic.POST("/sso/login", userSSOLogin)
		rgPublic.GET("/sso/callback", SSOCallBack)

		rgAuth.POST("/sql/query", UserSQLQuery)
		rgAuth.POST("/result/export", ResultExport)
		rgAuth.GET("/result/download-link/sse", SSEHandle)
		rgAuth.GET("/result/download", DownloadFile)

		rgAuth.GET("/record/list", getUserAuditRecordHandler)

		rgAuth.GET("/:taskId/result", getQueryResult)
		rgAuth.GET("/sql/result/keys", getMapKeys)
		rgAuth.GET("/db/list", DBList)
	})

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
			// ErrorResp(ctx, "Jwt token not exist")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid,please check"})
			return
		}
		userClaim, err := ParseJWT(tokenList[1])
		if err != nil {
			// ErrorResp(ctx, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		ctx.Set("user_id", userClaim.UserID)
		ctx.Set("user_email", userClaim.Email)
		ctx.Next()
	}
}

func DBList(ctx *gin.Context) {
	pool := newDBPoolManager()
	list := pool.getDBList()
	SuccessResp(ctx, list, "get db list success")
}

// /api/v1/query
func UserSQLQuery(ctx *gin.Context) {
	// 防止伪造jwt请求
	userID, exist := ctx.Get("user_id")
	if !exist {
		ErrorResp(ctx, "User not exist")
		return
	}
	var q UserQuery
	ctx.ShouldBind(&q)
	log.Println(q)

	// SQL语法解析并校验（v2.0)  - 格式化SQL查询语句（确保规范化）
	sqlRaw, err := ParseSQL(q.Statement)
	if err != nil {
		DefaultResp(ctx, 1, nil, err.Error())
		return
	}
	// 提交异步任务入队(v1.0)
	// taskID := SubmitSQLTask(sqlRaw, q.Database, userID.(string))

	// 事件驱动：封装成Event推送到事件通道(v2.0)
	task := CreateSQLQueryTask(sqlRaw, q.Database, userID.(string))
	ep := GetEventProducer()
	ep.Produce(Event{
		Type:    "sql_query",
		Payload: task,
	})
	SuccessResp(ctx, map[string]string{
		"task_id": task.ID,
	}, "submit sql_query event success")
}

// 通过SSE返回结果数据 ？?
func getQueryResult(ctx *gin.Context) {
	taskID := ctx.Param("taskId")
	if taskID == "" {
		ErrorResp(ctx, "taskID is null")
		return
	}
	userResult, exist := ResultMap.Get(taskID)
	// 仅获取不到key的时候重新获取
	if !exist {
		DefaultResp(ctx, -1, nil, "SQL查询中.......")
		return
	}
	if val, ok := userResult.(*QueryResult); ok {
		if val.Error != nil {
			DefaultResp(ctx, 1, "", val.Error.Error())
			return
		}
		SuccessResp(ctx, gin.H{
			"result":     val.Results,
			"rows_count": val.RowCount,
			"query_time": val.QueryTime,
		}, "SUCCESS")
	}

}

func getMapKeys(ctx *gin.Context) {
	userResult := ResultMap.Keys()
	log.Println(userResult)
	SuccessResp(ctx, userResult, "Get resultMap all keys success")
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
	err := CreateUser(userInfo.Name, userInfo.Password, userInfo.Email)
	if err != nil {
		DefaultResp(ctx, 1, nil, err.Error())
	}
	// 返回创建信息
	SuccessResp(ctx, "token=...", "Get resultMap all keys success")
}

// 用户登录（鉴权）
func userLogin(ctx *gin.Context) {
	var loginInfo UserInfo
	ctx.ShouldBind(&loginInfo)
	// 通过数据库验证
	user, err := BasicLogin(loginInfo.Email, loginInfo.Password)
	if err != nil {
		DefaultResp(ctx, 1, nil, err.Error())
		return
	}
	token, err := GenerateJWT(user.ID, user.Name, user.Email)
	if err != nil {
		DefaultResp(ctx, 1, nil, err.Error())
	}
	SuccessResp(ctx, gin.H{
		"user_token": token,
		"user":       user.Name,
	}, "user login success")
}

func getQueryRecords(ctx *gin.Context) {
	err := AllAuditRecords()
	if err != nil {
		DefaultResp(ctx, 1, nil, err.Error())
		return
	}
	SuccessResp(ctx, "test ok", "Get query result success")
}

// 处理gitlab SSO登录
func userSSOLogin(ctx *gin.Context) {
	oa2 := GetOAuthConfig()
	state, err := SetState()
	if err != nil {
		DefaultResp(ctx, 1, nil, GenerateError("NoStateValue", err.Error()).Error())
		return
	}
	authURL := oa2.AuthCodeURL(state)
	log.Println("构造后的auth url:", authURL)
	// ctx.Redirect(http.StatusFound, authURL)
	// 构造authURL，由前端去跳转。
	SuccessResp(ctx, map[string]any{
		"redirect_url": authURL,
		"state":        state,
	}, "redirect to gitlab oauth")
}

// 身份提供商回调验证函数（用于Token置换）
func SSOCallBack(ctx *gin.Context) {
	// 防御CSRF攻击（确保请求state参数一致）
	reqState := ctx.Request.URL.Query().Get("state")
	if reqState == "" {
		DefaultResp(ctx, http.StatusBadRequest, nil, "Missing state parameter")
		return
	}
	_, exist := SessionMap.Get(reqState)
	if !exist {
		DefaultResp(ctx, http.StatusBadRequest, nil, "Invaild state parameter")
		return
	}
	// 清理缓存
	SessionMap.Del(reqState)

	// 获取授权码
	oa2 := GetOAuthConfig()
	code := ctx.Request.URL.Query().Get("code")
	token, err := oa2.Exchange(context.Background(), code)
	if err != nil {
		ErrorResp(ctx, "Failed to exchange token:"+err.Error())
		return
	}
	// log.Println("DEBUG>>>", token)

	// 通过获取身份提供商的token中的用户信息，构造我们application的token
	client := oauthConf.Client(context.Background(), token)
	appConf := GetAppConfig()
	resp, err := client.Get(appConf.SSOEnv.ClientAPI)
	if err != nil {
		ErrorResp(ctx, "Failed to get user info:"+err.Error())
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
		ErrorResp(ctx, "decode user info is failed, "+err.Error())
		return
	}
	// 完成数据库相关的逻辑
	userId, err := SSOLogin(gitlabUserInfo.Name, gitlabUserInfo.Email)
	if err != nil {
		ErrorResp(ctx, "sso login failed, "+err.Error())
		return
	}
	// log.Println(gitlabUserInfo)
	appToken, err := GenerateJWT(userId, gitlabUserInfo.Name, gitlabUserInfo.Email)
	if err != nil {
		DefaultResp(ctx, 1, nil, err.Error())
	}
	SuccessResp(ctx, gin.H{
		"user_token": appToken,
		"user":       gitlabUserInfo.Name,
	}, "sso login success")
}

// 结果集导出路由逻辑
func ResultExport(ctx *gin.Context) {
	userId, exist := ctx.Get("user_id")
	if !exist {
		ErrorResp(ctx, "User not exist")
		return
	}
	var reqBody ExportTask
	ctx.ShouldBindJSON(&reqBody)
	export := SubmitExportTask(reqBody.ID, reqBody.Type, StrToUint(userId.(string)))

	SuccessResp(ctx, gin.H{
		"task_id":  export.ID,
		"filename": export.FileName,
	}, "export file task start...")
}

func DownloadFile(ctx *gin.Context) {
	taskId := ctx.Query("task_id")
	if taskId == "" {
		log.Println("debug: >> task id is null, invaild")
		DefaultResp(ctx, 1, nil, "param taskid is invalid")
		return
	}
	// 应该去指定地方查找filename
	mapVal, exist := ExportWorkMap.Get(taskId)
	if !exist {
		DefaultResp(ctx, 4, nil, "result file is not exist,may be cleaned")
		return
	}
	exportResult, ok := mapVal.(*ExportResult)
	if !ok {
		DefaultResp(ctx, 4, nil, "result file type not match")
		return
	}

	log.Println("[Download] download start...", exportResult.FilePath)
	// 判断要下载的文件
	if _, err := os.Stat(exportResult.FilePath); err != nil {
		// pwd, _ := os.Getwd()
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "文件不存在"})
		return
	}
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", exportResult.FilePath))
	ctx.File(exportResult.FilePath)
	log.Println("[Download] download completed")
	// SuccessResp(ctx, nil, "download success!!")
}

// SSE处理
func SSEHandle(ctx *gin.Context) {
	ctx.Header("Content-Type", "text/event-stream")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Connection", "keep-alive")

	_, exist := ctx.Get("user_id")
	if !exist {
		ErrorResp(ctx, "User not exist")
		return
	}
	// 从Parmas山获取taskId
	taskId := ctx.Query("task_id")
	if taskId == "" {
		log.Println("[TaskError] taskId is null,Abort!!!")
		return
	}

	// SSE处理逻辑超时控制
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	// 获取对应taskId的<导出对象>信息
	mapVal, exist := ExportWorkMap.Get(taskId)
	if !exist {
		log.Println("[NotExist] export result not exist,exit(1)")
		return
	}
	exportJob, ok := mapVal.(*ExportResult)
	if !ok {
		log.Println("[TypeNotMatch] export result type is not match,exit(1)")
		return
	}
	for {
		select {
		// 等待通知export结束
		case <-exportJob.Done:
			// 判断是否有错误
			if exportJob.Error != nil {
				log.Println("[ExportFailed] export task is failed ==>", exportJob.Error.Error())
				// 此时SSE连接已开，必须返回错误消息和关闭sse
				sseContent := sseEvent{
					ID:    2,
					Event: "error",
					Data:  exportJob.Error.Error(),
				}
				SSEMsgOnSend(ctx, &sseContent)
				// 发送完毕关闭连接
				sseContent = sseEvent{
					ID:    4,
					Event: "closed",
					Data:  "",
				}
				SSEMsgOnSend(ctx, &sseContent)
				return
			}
			log.Println("[Completed] export task done")
			// 发送初始化连接确认(discard)

			// 生成签名的URL下载链接
			// uri := GenerateSignedURI(taskId)
			downloadURL := fmt.Sprintf("/result/download?task_id=%s", taskId)
			sseContent := sseEvent{
				ID:    0,
				Event: "download_ready",
				Data:  downloadURL,
			}
			SSEMsgOnSend(ctx, &sseContent)

			// 发送完毕关闭连接
			sseContent = sseEvent{
				ID:    4,
				Event: "closed",
				Data:  "",
			}
			SSEMsgOnSend(ctx, &sseContent)
			return
		case <-timeoutCtx.Done():
			log.Println("[TimeOut] sse handle timeout,exit 1")
			return
		default:
			log.Println("[Wait] waiting export task done")
			time.Sleep(time.Second * 2)
		}
	}

}

// 失败的SSE Msg
func SSEMsgOnSend(ctx *gin.Context, event *sseEvent) {
	sseMsgJSON, err := json.Marshal(event)
	if err != nil {
		log.Println("[JSONMarshalError] json data masrshal error")
		return
	}
	sendMsg := fmt.Sprintf("data: %s\n\n", sseMsgJSON)
	ctx.Writer.Write([]byte(sendMsg))
	ctx.Writer.Flush()
}

// 获取指定用户的日志审计
func getUserAuditRecordHandler(ctx *gin.Context) {
	val, exist := ctx.Get("user_id")
	if !exist {
		ErrorResp(ctx, "server parse user is failed")
		return
	}
	userId, ok := val.(string)
	if !ok {
		ErrorResp(ctx, "convert type is failed")
		return
	}
	recordData, err := GetAuditRecordByUserID(userId)
	if err != nil {
		ErrorResp(ctx, err.Error())
		return
	}
	SuccessResp(ctx, recordData, "get audit records by userid")
}
