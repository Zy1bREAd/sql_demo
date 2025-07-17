package apis

// // 封装审计事件接口
// type AuditEvent interface{
// 	EventType() string

// }

func (v2 *AuditRecordV2) InsertOne(e string) error {
	v2.EventType = e
	db := HaveSelfDB()
	tx := db.conn.Begin()
	// 避免携带默认值插入污染导出相关信息
	result := selfDB.conn.Create(&v2)
	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}
	if result.RowsAffected != 1 {
		tx.Rollback()
		return GenerateError("InsertRecordError", "insert audit record is failed")
	}
	tx.Commit()

	return nil
}
