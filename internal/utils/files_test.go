package utils

import "testing"

func TestFileClean(T *testing.T) {
	filePath := "/tmp/sql_demo_export_file/result_export_all_6c6e3b46-6446-463f-9d2b-f664f24b5368_20250830004043.xlsx.xlsx"
	FileClean(filePath)
}
