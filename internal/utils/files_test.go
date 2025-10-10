package utils

import (
	"log"
	"testing"
	"time"
)

func TestFileClean(T *testing.T) {
	filePath := "/tmp/sql_demo_export_file/result_export_all_6c6e3b46-6446-463f-9d2b-f664f24b5368_20250830004043.xlsx.xlsx"
	FileClean(filePath)
}

func TestCSVResultExport(T *testing.T) {
	// 仅导出
	data1 := map[string]any{
		"id":   2,
		"name": "oceanwang",
	}
	data2 := map[string]any{
		"id":   42,
		"name": "edient",
	}

	csvData := []map[string]any{
		data1, data2,
	}
	csvRes := CSVResult{
		BasePath: "/tmp/sql_demo_export_file",
		FileName: "result_export_test" + time.Now().String(),
		Data:     csvData,
	}
	err := csvRes.Convert()
	if err != nil {
		log.Fatalln(err.Error())
	}
}
