package apis

import (
	"fmt"
	"log"
	"sync"
	"time"
)

var ResultMap *ResultCaches = &ResultCaches{cache: &sync.Map{}}

type QueryResult struct {
	ID        string           // task id
	Results   []map[string]any // 结果集列表
	QueryRaw  string           // 查询的原生SQL
	RowCount  int              // 返回结果条数
	QueryTime float64          // 查询花费的时间
	Error     error
	// ExpireTime time.Time // 结果集过期时间（用于自动清理）
}

func (qr *QueryResult) SetExpireTime(s int) {
	time.AfterFunc(time.Duration(s)*time.Second, func() {
		CleanQueue <- qr.ID
	})

}

// 仅针对QueryResult结果集的并发安全哈希表
type ResultCaches struct {
	cache *sync.Map
}

// 添加kv
func (rc *ResultCaches) Set(taskId string, result *QueryResult) {
	rc.cache.Store(taskId, result) // 应该存储结果集结构体
}

// 获取Key对应的values
func (rc *ResultCaches) Get(taskId string) (*QueryResult, error) {
	val, exist := rc.cache.Load(taskId)
	fmt.Println(val, exist)
	if !exist {
		return nil, GenerateError("GetResultError", "result key is not exist")
	}
	if val, ok := val.(*QueryResult); ok {
		return val, nil
	}
	return nil, GenerateError("GetResultError", "result is not `QueryResult` type")
}

// 删除Key
func (rc *ResultCaches) Del(taskId string) {
	rc.cache.Delete(taskId)
}

func (rc *ResultCaches) Keys() []string {
	allKey := []string{}
	rc.cache.Range(func(key, value any) bool {
		if val, ok := key.(string); ok {
			allKey = append(allKey, val)
		}
		return true
	})
	return allKey
}

// 清理所有Keys
func (rc *ResultCaches) Clean() {
	keys := rc.Keys()
	for _, k := range keys {
		rc.Del(k)
	}
	log.Println("housekeeping completed.")
}

// 遍历sync.Map中的kv（DEBUG）
func (rc *ResultCaches) Range() {
	rc.cache.Range(func(key, value any) bool {
		fmt.Printf("sync.Map key=%v , values=%v", key, value)
		return true
	})
}
