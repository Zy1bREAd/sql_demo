package apis

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
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
	r.Run("localhost:21899")
}

// 初始化基础路由
func InitBaseRoutes() {
	RegisterRoute(func(rgPublic, rgAuth *gin.RouterGroup) {
		rgAuth.POST("/query", QueryForGin)
		rgAuth.POST("/result", getQueryResult)
		rgAuth.GET("/keys", getMapKeys)
		rgPublic.POST("/register", userCreate)
		rgPublic.POST("/login", userLogin)
		rgAuth.GET("/records", userLogin)
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
		if len(tokenList) != 2 || tokenList[0] != "Bearer:" {
			// ErrorResp(ctx, "Jwt token not exist")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid,please check"})
			return
		}
		fmt.Println(tokenList)
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

// /api/v1/query
func QueryForGin(ctx *gin.Context) {
	// 防止伪造jwt请求
	userID, exist := ctx.Get("user_id")
	if !exist {
		ErrorResp(ctx, "User not exist")
		return
	}
	var q UserQuery
	ctx.ShouldBind(&q)
	fmt.Println(q)
	// 提交异步任务入队
	taskID := SubmitSQLTask(q.Statement, q.Database, userID.(string))
	SuccessResp(ctx, map[string]string{
		"task_id": taskID,
	}, "sql query task enqueue")
}

func getQueryResult(ctx *gin.Context) {
	var q UserQuery
	ctx.BindJSON(&q)
	userResult, err := ResultMap.Get(q.TaskID)
	if err != nil {
		ErrorResp(ctx, err.Error())
		return
	} else if userResult.Error != nil {
		ErrorResp(ctx, userResult.Error.Error())
		return
	}
	SuccessResp(ctx, userResult.Results, "Get query result success")
}

func getMapKeys(ctx *gin.Context) {
	userResult := ResultMap.Keys()
	fmt.Println(userResult)
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
		ErrorResp(ctx, err.Error())
	}
	// 返回创建信息
	SuccessResp(ctx, "token=...", "Get resultMap all keys success")
}

// 用户登录（鉴权）
func userLogin(ctx *gin.Context) {
	var loginInfo UserInfo
	ctx.ShouldBind(&loginInfo)
	user, err := Login(loginInfo.Email, loginInfo.Password)
	if err != nil {
		ErrorResp(ctx, err.Error())
		return
	}
	token, err := GenerateJWT(user.ID, user.Name, user.Email)
	if err != nil {
		ErrorResp(ctx, err.Error())
	}
	SuccessResp(ctx, gin.H{
		"user_token": token,
	}, "user login success")
}

func getQueryRecords(ctx *gin.Context) {
	err := AllAuditRecords()
	if err != nil {
		ErrorResp(ctx, err.Error())
		return
	}
	SuccessResp(ctx, "test ok", "Get query result success")
}
