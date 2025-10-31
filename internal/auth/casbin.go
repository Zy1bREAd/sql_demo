package auth

import (
	"sync"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
)

var once sync.Once
var pc *PermissionControl

type PermissionControl struct {
	*casbin.Enforcer
}

func InitCasbin() {
	once.Do(func() {
		adapter, err := gormadapter.NewAdapter("mysql", "oceanwang:uxje67pbQQUP@tcp(10.0.12.8:23366)/")
		if err != nil {
			panic(err)
		}
		enforcer, err := casbin.NewEnforcer("./configs/rbac_model.conf", adapter)
		if err != nil {
			panic(err)
		}
		enforcer.LoadPolicy()
		if pc == nil {
			pc = &PermissionControl{
				Enforcer: enforcer,
			}
		}

		// ! 默认的RBAC权限（区分运维和开发组）
		pc.Enforcer.AddPolicy("infra", "sql-task", "approval")
		pc.Enforcer.AddPolicy("infra", "sql-task", "online")
		pc.Enforcer.AddPolicy("devloper", "sql-task", "approval")
		pc.Enforcer.AddGroupingPolicy("oceanwang", "infra")
		pc.Enforcer.SavePolicy()
	})
}

func GetCasbin() *PermissionControl {
	return pc
}
