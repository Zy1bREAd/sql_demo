package apis

import (
	"fmt"
	"log"
	"sync"
	"time"
)

var ResultMap *CachesMap = &CachesMap{cache: &sync.Map{}}

type QueryResult struct {
	RowCount   int     // 返回结果条数
	QueryTime  float64 // 查询花费的时间
	HandleTime float64 // 处理结果集的时间
	ID         string  // task id
	QueryRaw   string  // 查询的原生SQL
	Error      error
	Results    []map[string]any // 结果集列表
	// ExpireTime time.Time // 结果集过期时间（用于自动清理）
}

type QResultGroup struct {
	GID      string
	resGroup []*QueryResult
}

// 仅针对QueryResult结果集的并发安全哈希表
type CachesMap struct {
	cache *sync.Map
}

// 添加kv
// ! 使用uint来避免负数，使用0代表无限，大于0都是正常的过期时间。
func (rc *CachesMap) Set(key string, values any, expireTime uint, taskType int) {
	rc.cache.Store(key, values) // 应该存储结果集结构体
	if expireTime > 0 {
		go func() {
			task := cleanTask{
				ID:   key,
				Type: taskType,
			}
			time.AfterFunc(time.Duration(expireTime)*time.Second, func() {
				// CleanQueue <- task
				ep := GetEventProducer()
				ep.Produce(Event{
					Type:    "clean_task",
					Payload: task,
				})
			})
		}()
	}

}

// 获取Key对应的values
func (rc *CachesMap) Get(key string) (any, bool) {
	return rc.cache.Load(key)
}

// 删除Key
func (rc *CachesMap) Del(taskId string) {
	rc.cache.Delete(taskId)
}

func (rc *CachesMap) Keys() []string {
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
func (rc *CachesMap) Clean() {
	keys := rc.Keys()
	for _, k := range keys {
		rc.Del(k)
	}
	log.Println("housekeeping completed.")
}

// 遍历sync.Map中的kv（DEBUG）
func (rc *CachesMap) Range() {
	rc.cache.Range(func(key, value any) bool {
		fmt.Printf("sync.Map key=%v , values=%v", key, value)
		return true
	})
}
