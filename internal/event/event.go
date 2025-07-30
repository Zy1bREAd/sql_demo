package event

import (
	"context"
	"fmt"
	"sql_demo/internal/utils"
	"sync"
)

// var globalEventChannel chan Event // 全局事件channel
var eventProducer *EventProducer
var eventDispatcher *EventDispatcher

type Event struct {
	Type    string
	Payload any // 事件具体信息
}

// ! 事件生产者
type EventProducer struct {
	eventChan chan Event // 全局事件通道
}

func (ep *EventProducer) Channel() chan Event {
	return ep.eventChan
}

func GetEventProducer() *EventProducer {
	if eventProducer == nil {
		eventProducer = &EventProducer{}
	}
	return eventProducer
}

func (ep *EventProducer) Init(eventCh chan Event) {
	ep.eventChan = eventCh
}

// 事件产生核心
func (ep *EventProducer) Produce(e Event) {
	if ep.eventChan == nil {
		utils.ErrorPrint("EventChannel", "eventChan is not init")
		return
	}
	select {
	case ep.eventChan <- e:
		utils.DebugPrint("事件产生", e)
	default:
		// 全局事件生产channel已满
		fmt.Println("全局事件通道已满，请稍后...", ep.eventChan)
	}
}

// ! 事件调度者
type EventDispatcher struct {
	eventChan  chan Event                      // 全局事件通道
	HandlerMap map[string]*EventHandlerWrapper // 对于事件路由的处理映射
	mapMutex   sync.RWMutex                    // 保护事件路由Map的读写锁
	Processer  int                             // 工人数量
	stopChan   chan struct{}
}

func (ed *EventDispatcher) Stop() {
	close(ed.eventChan) // 不再接收新的Event
	close(ed.stopChan)  // 触发EventWorker的停止
	for _, handler := range ed.HandlerMap {
		close(handler.stopCh)
	}
}

func (ed *EventDispatcher) Init(workerNum int, eventCh chan Event) {
	ed.eventChan = eventCh
	ed.Processer = workerNum
	ed.HandlerMap = make(map[string]*EventHandlerWrapper)
}

func GetEventDispatcher() *EventDispatcher {
	if eventDispatcher == nil {
		eventDispatcher = &EventDispatcher{}
	}
	return eventDispatcher
}

// 动态注册Handler
func (ed *EventDispatcher) RegisterHandler(eventType string, handler EventHandler, workerNum int) error {
	ed.mapMutex.Lock()
	defer ed.mapMutex.Unlock()
	// 预先定义好事件（硬编码-写死）
	// ed.HandlerMap["sql_query"] = NewQueryEventHandler(3)
	if _, exist := ed.HandlerMap[eventType]; exist {
		return utils.GenerateError("EventHandlerError", "事件Handler已被注册")
	}
	wrapper := &EventHandlerWrapper{
		handler:   handler,
		queue:     make(chan Event, 10),
		processor: workerNum,
	}
	wrapper.Start()
	ed.HandlerMap[eventType] = wrapper

	return nil
}

// 2.0路由事件
func (ed *EventDispatcher) Dispatch(ctx context.Context) {
	if ed.Processer == 0 {
		utils.ErrorPrint("DispatcherInit", "dispatcher init is failed...")
		return
	}
	fmt.Printf("[事件路由] 启动 %d 个 dispatcher\n", ed.Processer)
	for i := 0; i < ed.Processer; i++ {
		go func() {
			for {
				select {
				case event := <-ed.eventChan:
					err := ed.processEvent(event)
					if err != nil {
						utils.DebugPrint("EventRouteError", err.Error())
						return
					}
				case <-ed.stopChan:
					utils.DebugPrint("EventRouteStop", "收到退出信号，退出当前调度者")
					return
				case <-ctx.Done():
					utils.DebugPrint("EventRouteStop", "收到全局退出信号，退出所有")
					ed.Stop()
					return
				}
			}
		}()
	}
}

func (ed *EventDispatcher) processEvent(e Event) error {
	ed.mapMutex.Lock()
	handler, exist := ed.HandlerMap[e.Type]
	ed.mapMutex.Unlock()
	if !exist {
		utils.DebugPrint("HandlerNotFound", "无处理者注册，事件类型="+e.Type)
		return utils.GenerateError("HandlerNotFound", "无处理者注册，事件类型="+e.Type)
	}
	// 将事件路由到对应的EventHandler中来执行。
	select {
	case handler.queue <- e:
		return nil
	default:
		utils.DebugPrint("QueueisFull", "队列已满")
		return utils.GenerateError("QueueFullError", "队列已满，阻塞等待")
	}
}

// ! 事件处理者接口（实现该接口的实例会是真正操作er）
type EventHandler interface {
	Work(context.Context, Event) error
	Name() string
	// Stop()
}

// 封装一层事件处理者
type EventHandlerWrapper struct {
	handler   EventHandler // 实际EventHandler
	queue     chan Event
	processor int // 处理者数量
	stopCh    chan struct{}
}

func (wrapper *EventHandlerWrapper) Start() {
	fmt.Printf("[%s] 启动 %d 个 Worker\n", wrapper.handler.Name(), wrapper.processor)
	for i := 0; i < wrapper.processor; i++ {
		// 开启多个goroutine来进入EventHandler Loop监听事件消息来工作
		go wrapper.workLoop()
	}
}

func (wrapper *EventHandlerWrapper) workLoop() {
	for {
		select {
		case event, ok := <-wrapper.queue:
			if !ok {
				fmt.Println("队列已被关闭")
				return
			}
			ctx, cancel := context.WithCancel(context.Background()) // 正常取决于Event中的事件超时
			err := wrapper.handler.Work(ctx, event)
			cancel()
			if err != nil {
				// 判断错误是否严重不可逆，来决定是否中断Worker
				utils.DebugPrint("EventHandlerError", err)
				return
			}
		case <-wrapper.stopCh:
			utils.DebugPrint("EventHandlerExit", "正常收到信号，关闭Handler处理")
			return
		}
	}
}
