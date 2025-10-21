package core

import (
	"sql_demo/internal/event"
	"sync"
	"time"
)

// ! CahceMap 内存Map集，用作全局变量。
var ResultMap *CachesMap = &CachesMap{sync.Map{}}      // 存储结果集（TaskID -> Result）
var SessionMap *CachesMap = &CachesMap{sync.Map{}}     // 存储SSO登录State参数的Map
var QueryTaskMap *CachesMap = &CachesMap{sync.Map{}}   // 存储查询任务相关信息的映射表（任务 -> 详细QueryTask数据)
var ExportWorkMap *CachesMap = &CachesMap{sync.Map{}}  //导出工作的映射表(任务 -> 结果)
var GitLabIssueMap *CachesMap = &CachesMap{sync.Map{}} // GitLab Issue和Task Id的映射表(任务 -> GitLab Issue)
var CheckTaskMap *CachesMap = &CachesMap{sync.Map{}}   // 存储检查任务后的数据（包含解析后SQL的结构体数据，以切片的形式存储SQLForParseV2）
var APITaskBodyMap *CachesMap = &CachesMap{sync.Map{}} // 用于存储调用API创建SQL任务的Task Body

// 并发安全哈希表
type CachesMap struct {
	sync.Map
}

// ! 使用uint来避免负数，使用0代表无限，大于0都是正常的过期时间。
func (cache *CachesMap) Set(key any, values any, expireTime uint, taskKindFlag int) {
	cache.Store(key, values)
	if expireTime > 0 {
		go func() {
			var task CleanTask
			switch k := key.(type) {
			case string:
				task = CleanTask{
					UUID: k,
					Kind: taskKindFlag,
				}
			case int64:
				task = CleanTask{
					ID:   k,
					Kind: taskKindFlag,
				}
			}
			time.AfterFunc(time.Duration(expireTime)*time.Second, func() {
				// CleanQueue <- task
				ep := event.GetEventProducer()
				ep.Produce(event.Event{
					Type:    "clean_task",
					Payload: task,
					MetaData: event.EventMeta{
						Source:    "cache",
						Timestamp: time.Now().Format("20060102150405"),
					},
				})
			})
		}()
	}

}

// 获取Key对应的values
func (cache *CachesMap) Get(key any) (any, bool) {
	return cache.Load(key)
}

// 删除Key
func (cache *CachesMap) Del(key any) {
	cache.Delete(key)
}

func (cache *CachesMap) Keys() []any {
	allKey := []any{}
	cache.Range(func(key, value any) bool {
		if val, ok := key.(int64); ok {
			allKey = append(allKey, val)
		} else if val, ok := key.(string); ok {
			allKey = append(allKey, val)
		}
		return true
	})
	return allKey
}

// 清理所有Keys
func (cache *CachesMap) Clean() {
	keys := cache.Keys()
	for _, k := range keys {
		cache.Del(k)
	}
}
