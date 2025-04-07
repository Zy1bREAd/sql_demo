package apis

type QueryResult struct {
	ID        string           // task id
	Results   []map[string]any // 结果集列表
	QueryRaw  string           // 查询的原生SQL
	RowCount  int              // 返回结果条数
	QueryTime float64          // 查询花费的时间
	Error     error
}
