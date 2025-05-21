package apis

import (
	"fmt"
	"log"
	"sync"
	"time"
)

var ResultMap *CachesMap = &CachesMap{cache: &sync.Map{}}

type QueryResult struct {
	ID        string           // task id
	Results   []map[string]any // 结果集列表
	QueryRaw  string           // 查询的原生SQL
	RowCount  int              // 返回结果条数
	QueryTime float64          // 查询花费的时间
	Error     error
	// ExpireTime time.Time // 结果集过期时间（用于自动清理）
}

// 仅针对QueryResult结果集的并发安全哈希表
type CachesMap struct {
	cache *sync.Map
}

// 添加kv
func (rc *CachesMap) Set(key string, values any, expireTime int) {
	rc.cache.Store(key, values) // 应该存储结果集结构体
	if expireTime > 0 {
		go func() {
			time.AfterFunc(time.Duration(expireTime)*time.Second, func() {
				CleanQueue <- key
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

// // 转换CSV文件
// func ConvertMapToCSV(data []map[string]any, fileName string) error {

// }
