package apis

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// test
var testCh chan struct{} = make(chan struct{}, 10)

// var globalEventChannel chan Event // 全局事件channel
var eventProducer *EventProducer
var eventDispatcher *EventDispatcher
var eventOnce sync.Once

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

func NewEventProducer(eventCh chan Event) *EventProducer {
	return &EventProducer{
		eventChan: eventCh,
	}
}

func GetEventProducer() *EventProducer {
	return eventProducer
}

// 事件产生核心
func (ep *EventProducer) Produce(e Event) {
	select {
	case ep.eventChan <- e:
		DebugPrint("事件产生", e)
	default:
		// 全局事件生产channel已满
		fmt.Println("全局事件通道已满，请稍后...")
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

func InitEventDrive(ctx context.Context, bufferSize int) {
	eventOnce.Do(func() {
		globalEventChannel := make(chan Event, bufferSize)
		// 生产者初始化
		if eventProducer == nil {
			eventProducer = NewEventProducer(globalEventChannel)
		}
		// 调度者初始化（事件路由注册）
		if eventDispatcher == nil {
			eventDispatcher = NewEventDispatcher(3, globalEventChannel)
			registerMap := map[string]func() EventHandler{
				"sql_query":         NewQueryEventHandler,
				"save_result":       NewResultEventHandler,
				"clean_task":        NewCleanEventHandler,
				"export_result":     NewExportEventHandler,
				"file_housekeeping": NewHousekeepingEventHandler,
			}
			for k, handler := range registerMap {
				err := eventDispatcher.registerHandler(k, handler(), 3)
				if err != nil {
					panic(err)
				}
			}
		}
	})
	// 启动调度者开始调度事件
	ed := GetEventDispatcher()
	go ed.Dispatch(ctx)
}

func NewEventDispatcher(workerNum int, eventCh chan Event) *EventDispatcher {
	return &EventDispatcher{
		eventChan:  eventCh,
		HandlerMap: make(map[string]*EventHandlerWrapper),
		Processer:  workerNum,
	}
}

func GetEventDispatcher() *EventDispatcher {
	return eventDispatcher
}

// 动态注册Handler
func (ed *EventDispatcher) registerHandler(eventType string, handler EventHandler, workerNum int) error {
	ed.mapMutex.Lock()
	defer ed.mapMutex.Unlock()
	// 预先定义好事件（硬编码-写死）
	// ed.HandlerMap["sql_query"] = NewQueryEventHandler(3)
	if _, exist := ed.HandlerMap[eventType]; exist {
		return GenerateError("EventHandlerError", "事件Handler已被注册")
	}
	// ed.HandlerMap[eventType] = handler		// 该方式仍然存储实际EventHandler
	wrapper := &EventHandlerWrapper{
		handler:   handler,
		queue:     make(chan Event, 10),
		processor: workerNum,
	}
	wrapper.Start()
	ed.HandlerMap[eventType] = wrapper

	return nil
}

// 过去1.0版调度者即执行者的逻辑（不会分开独立控制）
// func (ed *EventDispatcher) workLoop() {
// 	for i := 0; i < ed.Processer; i++ {
// 		go func() {
// 			for {
// 				select {
// 				case event := <-ed.eventChan:
// 					fmt.Println("事件调度 >>>", event.Type, event.Payload)
// 					ed.processEvent(event)
// 				case <-ed.stopChan:
// 					fmt.Println("收到退出信号，退出调度者")
// 					return
// 				default:
// 					fmt.Println("无事件调度，有可能eventChannel无数据")
// 				}
// 				fmt.Println("读取消息Loop一次结束")
// 			}
// 		}()
// 	}
// }

// 2.0路由事件
func (ed *EventDispatcher) Dispatch(ctx context.Context) {
	fmt.Printf("[事件路由] 启动 %d 个 dispatcher\n", ed.Processer)
	for i := 0; i < ed.Processer; i++ {
		go func() {
			for {
				select {
				case event := <-ed.eventChan:
					err := ed.processEvent(event)
					if err != nil {
						DebugPrint("EventRouteError", err.Error())
						return
					}
				case <-ed.stopChan:
					DebugPrint("EventRouteStop", "收到退出信号，退出当前调度者")
					return
				// default:
				// DebugPrint("EventRoute???", "无事件调度，有可能eventChannel无数据")
				case <-ctx.Done():
					DebugPrint("EventRouteStop", "收到全局退出信号，退出所有")
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
		DebugPrint("HandlerNotFound", "无处理者注册，事件类型="+e.Type)
		return GenerateError("HandlerNotFound", "无处理者注册，事件类型="+e.Type)
	}
	// 将事件路由到对应的EventHandler中来执行。
	select {
	case handler.queue <- e:
		return nil
	default:
		DebugPrint("QueueisFull", "队列已满")
		return GenerateError("QueueFullError", "队列已满，阻塞等待")
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
			fmt.Printf("事件类型=%s\n", event.Type)
			if !ok {
				fmt.Println("队列已被关闭")
				return
			}
			ctx, cancel := context.WithCancel(context.Background()) // 正常取决于Event中的事件超时
			err := wrapper.handler.Work(ctx, event)
			cancel()
			if err != nil {
				// 判断错误是否严重不可逆，来决定是否中断Worker
				DebugPrint("EventHandlerError", err)
				return
			}
		case <-wrapper.stopCh:
			DebugPrint("EventHandlerExit", "正常收到信号，关闭Handler处理")
			return
		}
	}
}

// 具体实现事件处理者
type QueryEventHandler struct {
}

func NewQueryEventHandler() EventHandler {
	return &QueryEventHandler{}
}

func (eh *QueryEventHandler) Name() string {
	return "查询事件处理者"
}

func (eh *QueryEventHandler) Work(ctx context.Context, e Event) error {
	// 防止重复执行任务?
	// 判断哪种类型的QueryTask
	switch t := e.Payload.(type) {
	case *QueryTask:
		DebugPrint("SQL查询事件消费", t.ID)
		QueryTaskMap.Set(t.ID, t, 300, 1) // 存储查询任务信息
		ExcuteSQLTask(ctx, t)
		// 日志审计插入v2（不支持）
	case *QTaskGroup:
		// 支持多SQL
		DebugPrint("SQL查询Group事件消费", t.GID)
		QueryTaskMap.Set(t.GID, t, 300, 1)
		t.ExcuteTask(ctx)
	case *IssueQueryTask:
		DebugPrint("SQL查询事件消费", t.QTask.ID)
		QueryTaskMap.Set(t.QTask.ID, t, 300, 1) // 存储查询任务信息
		// Issue评论情况更新
		api := InitGitLabAPI()
		updateMsg := fmt.Sprintf("TaskId=%s is start work...", t.QTask.ID)
		api.CommentCreate(t.QIssue.ProjectID, t.QIssue.IID, updateMsg)
		ExcuteSQLTask(ctx, t.QTask)
		// 日志审计插入v2
		audit := AuditRecordV2{
			TaskID:    t.QTask.ID,
			UserID:    t.QTask.UserID,
			Payload:   t.QIssue.Description,
			ProjectID: t.QIssue.ProjectID,
			IssueID:   t.QIssue.IID,
		}
		err := audit.InsertOne("SQL_QUERY")
		if err != nil {
			ErrorPrint("AuditRecordV2", err.Error())
		}
	default:
		DebugPrint("TaskTypeError", "event payload type is incrroect")
		return GenerateError("TaskTypeError", "event payload type is incrroect")
	}
	return nil
}

// 消费事件、处理结果
type ResultEventHandler struct {
}

func NewResultEventHandler() EventHandler {
	return &ResultEventHandler{}
}

func (eh *ResultEventHandler) Name() string {
	return "结果事件处理者"
}

func (eh *ResultEventHandler) Work(ctx context.Context, e Event) error {
	switch res := e.Payload.(type) {
	case *QResultGroup:
		DebugPrint("查询结果事件消费", res.GID)
		ResultMap.Set(res.GID, res, 300, 0)
		testCh <- struct{}{}
	case *QueryResult:
		DebugPrint("查询结果事件消费", res.ID)
		//! 后期核心处理结果集的代码逻辑块
		ResultMap.Set(res.ID, res, 300, 0)
		testCh <- struct{}{}
		// 获取ID对应的task
		val, _ := QueryTaskMap.Get(res.ID)
		v, ok := val.(*IssueQueryTask)
		if !ok {
			// 有可能是QueryTask，所以跳过
			return nil
		}
		// Issue评论情况更新
		api := InitGitLabAPI()
		updateMsg := fmt.Sprintf("TaskId=%s is completed", v.QTask.ID)
		api.CommentCreate(v.QIssue.ProjectID, v.QIssue.IID, updateMsg)
		if res.Error != nil {
			log.Printf("TaskId=%s TaskError=%s", res.ID, res.Error)
			err := api.CommentCreate(v.QIssue.ProjectID, v.QIssue.IID, res.Error.Error())
			if err != nil {
				DebugPrint("CommentError", "query task result comment is failed"+err.Error())
			}
		}
		// 存储结果、输出结果临时链接
		issContent, err := parseIssueDesc(v.QIssue.Description)
		if err != nil {
			api.CommentCreate(v.QIssue.ProjectID, v.QIssue.IID, "export result file is failed, "+res.Error.Error())
		}
		uuKey, tempURL := NewHashTempLink()
		err = SaveTempResult(uuKey, v.QTask.ID, 300, issContent.IsExport)
		if err != nil {
			DebugPrint("SaveTempResultError", "db save result link is failed "+err.Error())
		}
		api.CommentCreate(v.QIssue.ProjectID, v.QIssue.IID, tempURL)
		// 导出结果
		if issContent.IsExport {
			exportTask := SubmitExportTask(v.QTask.ID, "csv", v.QIssue.Author.ID)
			<-exportTask.Result.Done
		}
		// 自动关闭issue（表示完成）
		err = api.IssueClose(v.QIssue.ProjectID, v.QIssue.IID)
		if err != nil {
			DebugPrint("GitLabAPI", err.Error())
		}
		// 完成通知
		iss, err := api.IssueView(v.QIssue.ProjectID, v.QIssue.IID)
		if err != nil {
			DebugPrint("GitLabAPI", err.Error())
		}
		informBody := InformTemplate{
			UserName: v.QIssue.Author.Name,
			Action:   "Completed",
			Link:     iss.WebURL,
		}
		_ = InformRobot(informBody.Fill())
	default:
		fmt.Println("》》》没有匹配到的结果集类型")
	}
	return nil
}

type CleanEventHandler struct {
	cleanTypeMap     map[int]*CachesMap
	cleanTypeInfoMap map[int]string
}

func NewCleanEventHandler() EventHandler {

	return &CleanEventHandler{
		cleanTypeMap: map[int]*CachesMap{
			0: ResultMap,
			1: QueryTaskMap,
			2: SessionMap,
			3: ExportWorkMap,
		},
		cleanTypeInfoMap: map[int]string{
			0: "ResultMap",
			1: "QueryTaskMap",
			2: "SessionMap",
			3: "ExportWorkMap",
		},
	}
}

func (eh *CleanEventHandler) Name() string {
	return "清理事件处理者"
}

func (eh *CleanEventHandler) Work(ctx context.Context, e Event) error {
	body, ok := e.Payload.(cleanTask)
	if !ok {
		return GenerateError("TypeError", "event payload type is incrroect")
	}
	DebugPrint("清理结果事件消费", body.ID)
	//! 后期核心处理结果集的代码逻辑块
	mapOperator := eh.cleanTypeMap[body.Type]
	mapOperator.Del(body.ID)
	log.Printf("type=%v taskID=%s Cleaned Up", eh.cleanTypeInfoMap[body.Type], body.ID)
	return nil
}

// 结果导出者
type ExportEventHandler struct {
}

func NewExportEventHandler() EventHandler {

	return &ExportEventHandler{}
}

func (eh *ExportEventHandler) Name() string {
	return "导出结果事件处理者"
}

func (eh *ExportEventHandler) Work(ctx context.Context, e Event) error {
	body, ok := e.Payload.(*ExportTask)
	if !ok {
		return GenerateError("TypeError", "event payload type is incrroect")
	}
	//! 后期核心处理结果集的代码逻辑块
	DebugPrint("ExportTask", "export task "+body.ID+" is starting...")
	err := ExportSQLTask(ctx, body)
	if err != nil {
		// 添加错误信息
		body.Result.Error = err
		body.Result.FilePath += "_failed"
		body.Result.Done <- struct{}{}
		DebugPrint("ExportTask", "export task "+body.ID+" is failed,error: "+err.Error())
	}
	DebugPrint("ExportTask", "export task "+body.ID+" is completed")
	return nil
}

// 文件清理者
type HousekeepingEventHandler struct {
}

func NewHousekeepingEventHandler() EventHandler {

	return &HousekeepingEventHandler{}
}

func (eh *HousekeepingEventHandler) Name() string {
	return "文件清理事件处理者"
}

func (eh *HousekeepingEventHandler) Work(ctx context.Context, e Event) error {
	body, ok := e.Payload.(*ExportTask)
	if !ok {
		return GenerateError("TypeError", "event payload type is incrroect")
	}
	DebugPrint("文件清理事件消费", body.ID)
	//! 后期核心处理结果集的代码逻辑块
	FileClean(body.Result.FilePath)
	return nil
}
