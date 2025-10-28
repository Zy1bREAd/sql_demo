package core

import (
	"fmt"
	"testing"
	"time"
)

func TestCaches(t *testing.T) {
	InitKVCache()
	// p := &struct {
	// 	Name    string
	// 	Age     int
	// 	Address string
	// }{
	// 	Name:    "OceanWang",
	// 	Age:     25,
	// 	Address: "GDSZ",
	// }
	var pia *int
	*pia = 10
	c := GetKVCache()
	cKey := "gitlab-issue-body:1981547382529069056"
	ok := c.RistCache.SetWithTTL(cKey, pia, 10000, time.Second*60)
	if !ok {
		fmt.Println("not ok 1")
	}
	c.RistCache.Wait()
	// time.Sleep(1 * time.Second)
	val, ok := c.RistCache.Get(cKey)
	if !ok {
		fmt.Println("not ok 2")
	}
	fmt.Println(val)
}
