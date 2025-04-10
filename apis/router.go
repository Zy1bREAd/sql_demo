package apis

import (
	"fmt"
	"log"

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
	// rgPublic.GET("xxx", func(ctx *gin.Context) {})
	InitBaseRoutes()

	// 加载路由注册函数
	fmt.Println(fnRoutes)
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
	})

}

type UserQuery struct {
	Database  string `json:"db_name"`
	Statement string `json:"query_sql"` // 暂且是string类型
	TaskID    string `json:"task_id"`   // 任务ID
}

// /api/v1/query
func QueryForGin(ctx *gin.Context) {
	var q UserQuery
	ctx.BindJSON(&q)
	fmt.Println("user query params:", q)
	// 后续提交任务进行执行
	taskID := SubmitSQLTask(q.Statement)
	// 暂时取出结果看看（后续需要异步通知用户查看）
	ctx.JSON(200, gin.H{
		"status": 200,
		"msg":    "test",
		"data": map[string]string{
			"task_id": taskID,
		},
	})
}

func getQueryResult(ctx *gin.Context) {
	var q UserQuery
	ctx.BindJSON(&q)
	userResult, err := ResultMap.Get(q.TaskID)
	fmt.Println(q.TaskID)
	if err != nil {
		ctx.JSON(200, gin.H{
			"status": 500,
			"msg":    err.Error(),
			"data":   "",
		})
		return
	}
	ctx.JSON(200, gin.H{
		"status": 200,
		"msg":    "get result ok ",
		"data":   userResult.Results,
	})

}
