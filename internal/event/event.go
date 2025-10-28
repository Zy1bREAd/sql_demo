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
	Type     string
	Payload  any // 事件具体信息
	MetaData EventMeta
}

// 事件元数据
type EventMeta struct {
	Source    string `json:"source"`
	Timestamp string `json:"timestamp"`
	TraceID   string `json:"trace_id"`
	Operator  int    `json:"operator"`
	ProjectID uint   `json:"project_id"`
	IssueIID  uint   `json:"issue_iid"`
}

// ! 事件处理者接口（实现该接口的实例会是真正操作er）
type EventHandler interface {
	Work(context.Context, Event) error
	Name() string
	// Stop()
}

// ! 事件生产者
type EventProducer struct {
	eventChan chan Event // 全局事件通道
}

func GetEventProducer() *EventProducer {
	if eventProducer == nil {
		eventProducer = &EventProducer{}
	}
	return eventProducer
}

// 生产者初始化
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
	stopOnce   sync.Once                       // 确保只关闭一次
	stopChan   chan struct{}
}

func (ed *EventDispatcher) Stop() {
	ed.stopOnce.Do(func() {
		close(ed.eventChan) // 不再接收新的Event
		close(ed.stopChan)  // 触发EventWorker的停止
		for _, handler := range ed.HandlerMap {
			close(handler.stopCh)
		}
	})
}

// 事件分发者初始化
func (ed *EventDispatcher) Init(workerNum int, eventCh chan Event) {
	ed.eventChan = eventCh
	ed.Processer = workerNum
	ed.HandlerMap = make(map[string]*EventHandlerWrapper)
	ed.stopChan = make(chan struct{}, 1)
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
		stopCh:    make(chan struct{}, 1),
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
		utils.DebugPrint("HandlerQueueFull", "处理者队列已满")
		return utils.GenerateError("HandlerQueueFull", "处理者队列已满，阻塞等待")
	}
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
		case <-wrapper.stopCh:
			utils.DebugPrint("EventHandlerExit", fmt.Sprintf("正常收到信号，关闭 %s 处理", wrapper.handler.Name()))
			return
		case event, ok := <-wrapper.queue:
			if !ok {
				utils.ErrorPrint("HandlerQueueErr", "The Message is invalid")
				continue
			}
			ctx, cancel := context.WithCancel(context.Background()) // 正常取决于Event中的事件超时
			err := wrapper.handler.Work(ctx, event)
			if err != nil {
				// TODO: 判断错误是否严重不可逆，来决定是否中断Worker
				utils.ErrorPrint("EventHandlerError", err)
				cancel() // 显式取消
				return
			}
			cancel() // 显式取消
		}
	}
}
