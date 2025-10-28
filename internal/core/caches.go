package core

import (
	"log"
	"sql_demo/internal/utils"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto/v2"
)

// 全局变量：本地缓存
type KVCache struct {
	RistCache *ristretto.Cache[string, any]
}

var localCache KVCache
var initOnce sync.Once

// 初始化本地缓存
func InitKVCache() {
	initOnce.Do(func() {
		if localCache.RistCache == nil {
			cache, err := ristretto.NewCache(&ristretto.Config[string, any]{
				NumCounters: 1e7,
				MaxCost:     (1 << 20) * 100, // 100MB
				BufferItems: 64,
			})
			if err != nil {
				log.Fatalln("LocalCacheErr:" + err.Error())
				panic(err)
			}
			localCache.RistCache = cache
		}
	})
}

// 获取本地缓存
func GetKVCache() *KVCache {
	if localCache.RistCache == nil {
		utils.ErrorPrint("CacheInitErr", "KV Cache is not inited")
		return nil
	}
	return &localCache
	// defer cache.Close()
}

func CloseKVCache() {
	if localCache.RistCache == nil {
		utils.ErrorPrint("CacheInitErr", "KV Cache is not inited")
		return
	}
	localCache.Close()
}

func (c *KVCache) Ping() error {
	k := "health:ping"
	ok := c.RistCache.SetWithTTL(k, "pong", 0, time.Second*30)
	if !ok {
		return utils.GenerateError("CacheError", "Cache is no-health")
	}
	c.RistCache.Wait()
	_, ok = c.RistCache.Get(k)
	if !ok {
		return utils.GenerateError("CacheError", "Cache is no-health")
	}
	return nil
}

func (c *KVCache) Close() {
	c.RistCache.Close()
}

// 针对设置Int的Value，在基础上减少指定秒数的TTL
func (c *KVCache) AddCountVal(cKey string, n int) error {
	cVal, exist := c.RistCache.Get(cKey)
	if !exist {
		return utils.GenerateError("KeyNotExist", "Cache Key is not exist")
	}
	countVal, ok := cVal.(int)
	if !ok {
		return utils.GenerateError("ValueError", "Cache Value is not int type")
	}
	cTTL, ok := c.RistCache.GetTTL(cKey)
	if !ok {
		return utils.GenerateError("KeyNotExist", "Cache Key is expired")
	}
	if cTTL >= 10 {
		cTTL -= time.Second * 1
	}
	cTTL -= time.Second * 1
	c.RistCache.SetWithTTL(cKey, countVal+1, 1, cTTL)
	return nil
}
