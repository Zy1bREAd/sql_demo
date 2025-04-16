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

	rgPublic := r.Group("/api/v1/public")
	rgAuth := r.Group("/api/v1/")
	// 使用认证鉴权中间件
	rgAuth.Use(AuthMiddleware())
	InitBaseRoutes()

	// 加载路由注册函数
	for _, fn := range fnRoutes {
		fn(rgPublic, rgAuth)
	}
	r.Run(":8099")
}

// 初始化基础路由
func InitBaseRoutes() {
	RegisterRoute(func(rgPublic, rgAuth *gin.RouterGroup) {
		rgAuth.POST("/query", QueryForGin)
		rgAuth.POST("/result", getQueryResult)
		rgAuth.GET("/keys", getMapKeys)
		rgAuth.POST("/user_create", userCreate)
		rgPublic.POST("/login", userLogin)
	})

}

type UserQuery struct {
	Database  string `json:"db_name"`
	Statement string `json:"query_sql"`
	TaskID    string `json:"task_id"` // 任务ID
}

// 认证鉴权中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		reqToken := ctx.Request.Header.Get("Authorization")
		tokenList := strings.Split(reqToken, " ")
		if len(tokenList) != 2 {
			// ErrorResp(ctx, "Jwt token not exist")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token invalid"})
			return
		}
		fmt.Println(tokenList)
		_, err := ParseJWT(tokenList[1])
		if err != nil {
			// ErrorResp(ctx, err.Error())
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		ctx.Next()
	}
}

// /api/v1/query
func QueryForGin(ctx *gin.Context) {
	var q UserQuery
	ctx.BindJSON(&q)
	fmt.Println("user query params:", q)
	// 后续提交任务进行执行
	taskID := SubmitSQLTask(q.Statement, q.Database)
	// 暂时取出结果看看（后续需要异步通知用户查看）
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
