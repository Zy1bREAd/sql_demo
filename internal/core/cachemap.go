package core

import (
	"fmt"
	"sql_demo/internal/event"
	"sync"
	"time"
)

// ! CahceMap 内存Map集，用作全局变量。
var ResultMap *CachesMap = &CachesMap{cache: &sync.Map{}}      // 存储结果集（TaskID -> Result）
var SessionMap *CachesMap = &CachesMap{cache: &sync.Map{}}     // 存储SSO登录State参数的Map
var QueryTaskMap *CachesMap = &CachesMap{cache: &sync.Map{}}   // 存储查询任务相关信息的映射表（任务 -> 详细QueryTask数据)
var ExportWorkMap *CachesMap = &CachesMap{cache: &sync.Map{}}  //导出工作的映射表(任务 -> 结果)
var GitLabIssueMap *CachesMap = &CachesMap{cache: &sync.Map{}} // GitLab Issue和Task Id的映射表(任务 -> GitLab Issue)
var SQLStmtMap *CachesMap = &CachesMap{cache: &sync.Map{}}     // 存储解析后的SQL结构体数据。以切片的形式存储SQLForParseV2

// 并发安全哈希表
type CachesMap struct {
	cache *sync.Map
}

// ! 使用uint来避免负数，使用0代表无限，大于0都是正常的过期时间。
func (rc *CachesMap) Set(key string, values any, expireTime uint, taskType int) {
	rc.cache.Store(key, values)
	if expireTime > 0 {
		go func() {
			task := cleanTask{
				ID:   key,
				Type: taskType,
			}
			time.AfterFunc(time.Duration(expireTime)*time.Second, func() {
				// CleanQueue <- task
				ep := event.GetEventProducer()
				ep.Produce(event.Event{
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
}

// 遍历sync.Map中的kv（DEBUG）
func (rc *CachesMap) Range() {
	rc.cache.Range(func(key, value any) bool {
		fmt.Printf("sync.Map key=%v , values=%v", key, value)
		return true
	})
}
