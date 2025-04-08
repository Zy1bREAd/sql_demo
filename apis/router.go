package apis

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

// 定义路由注册函数
type FnRegisterRoute func(rgPublic *gin.RouterGroup, rgAuth *gin.RouterGroup)

// 定义需要注册的路由列表
var fnRoutes []FnRegisterRoute

// 添加路由注册函数
func RegisterRoute(fn FnRegisterRoute) {
	if fnRoutes == nil {
		log.Println("不需要注册")
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

	for _, fn := range fnRoutes {
		fn(rgPublic, rgAuth)
	}
	r.Run(":8099")
}

// 初始化基础路由
func InitBaseRoutes() {
	RegisterRoute(func(rgPublic, rgAuth *gin.RouterGroup) {
		rgPublic.POST("/query", QueryForGin)
	})
}

type UserQuery struct {
	Database  string `json:"db_name" binding:"required"`
	Statement string `json:"query_sql" binding:"required"` // 暂且是string类型
}

// /api/v1/query
func QueryForGin(ctx *gin.Context) {
	var q UserQuery
	ctx.BindJSON(&q)
	fmt.Println("user query params:", q)
	// 后续提交任务进行执行
	SubmitSQLTask(q.Statement)
	time.Sleep(5 * time.Second)
	// 暂时取出结果看看（后续需要异步通知用户查看）
	ctx.JSON(200, gin.H{
		"status": 200,
		"msg":    "test",
		"data":   "result...",
	})
}
