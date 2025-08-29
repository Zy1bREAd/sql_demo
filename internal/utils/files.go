package utils

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"

	"github.com/xuri/excelize/v2"
)

type ResultFiler interface {
	Convert() error
	ExtName() string
}

type CSVResult struct {
	BasePath string
	FileName string
	Data     []map[string]any
}

type ExcelResult struct {
	Index    int
	BasePath string
	FileName string
	Data     []map[string]any
}

func pathIsExist(base string) error {
	// 创建文件，不存在目录则创建
	_, err := os.Stat(base)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(base, 0755)
			if err != nil {
				log.Println("create a file path is failed ->", err.Error())
				return err
			}
		} else {
			log.Println("create a temp CSV file is failed ->", err.Error())
			return err
		}
	}
	return nil
}

func (exr *ExcelResult) ExtName() string {
	return ".xlsx"
}

func (exr *ExcelResult) CreateFile() error {
	filePath := exr.BasePath + "/" + exr.FileName + exr.ExtName()
	err := pathIsExist(exr.BasePath)
	if err != nil {
		return err
	}

	var f *excelize.File
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			f = excelize.NewFile()
		} else {
			excelFile, err := excelize.OpenFile(filePath)
			if err != nil {
				return GenerateError("ExcelOpenErr", err.Error())
			}
			f = excelFile
		}
	}
	defer f.Close()
	// 手动删除 Sheet1 工作表
	f.DeleteSheet("Sheet1")
	// 保存Excel文件
	if err := f.SaveAs(filePath); err != nil {
		return GenerateError("ExcelDataSaveErr", err.Error())
	}
	return nil
}

func (exr *ExcelResult) Convert() error {
	var f *excelize.File
	filePath := exr.BasePath + "/" + exr.FileName + exr.ExtName()
	f, err := excelize.OpenFile(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	// 创建Sheet工作表
	sheetName := fmt.Sprintf("Result %d", exr.Index)
	s, err := f.NewSheet(sheetName)
	if err != nil {
		return GenerateError("ConvertExcelFailed", err.Error())
	}
	f.SetActiveSheet(s)
	if exr.Data == nil {
		// 空数据直接返回
		if err := f.SaveAs(filePath); err != nil {
			return GenerateError("ExcelDataSaveErr", err.Error())
		}
		return nil
	}
	colsName := getHeadersData(exr.Data[0])
	err = writeRow(f, sheetName, 1, colsName)
	if err != nil {
		fmt.Println(GenerateError("TableHeaderError", err.Error()))
	}
	// 写入结果集数据
	for rowIdx, row := range exr.Data {
		rowData := getRowsData(row, colsName)
		err := writeRow(f, sheetName, rowIdx+2, rowData)
		if err != nil {
			return GenerateError("ExcelDataError", err.Error())
		}
	}

	// 保存Excel文件
	if err := f.SaveAs(filePath); err != nil {
		return GenerateError("ExcelDataSaveErr", err.Error())
	}
	return nil
}

func writeRow(f *excelize.File, sheetName string, rowNum int, data []string) error {
	// 将数据转换为单元格格式（A1, B1, ...）
	cell, err := excelize.CoordinatesToCellName(1, rowNum)
	if err != nil {
		return err
	}

	// 写入整行数据（支持批量写入）
	if err := f.SetSheetRow(sheetName, cell, &data); err != nil {
		return err
	}
	return nil

}

func (cr *CSVResult) ExtName() string {
	return ".csv"
}

// 转换成CSV文件并存储在本地
func (cr *CSVResult) Convert() error {
	err := pathIsExist(cr.BasePath)
	if err != nil {
		return err
	}

	filePath := cr.BasePath + "/" + cr.FileName + cr.ExtName()
	f, err := os.Create(filePath)
	if err != nil {
		return GenerateError("CreateFileErr", err.Error())
	}
	defer f.Close()
	// 制作表头数据
	w := csv.NewWriter(f)
	defer w.Flush()
	if cr.Data == nil {
		// 空数据直接返回
		return nil
	}
	colsName := getHeadersData(cr.Data[0])

	// 写入表头
	if err := w.Write(colsName); err != nil {
		log.Println("write headers csv file is error,", err.Error())
		return GenerateError("CSVFileErr", err.Error())
	}

	// 写入结果集数据
	for _, row := range cr.Data {
		rowData := getRowsData(row, colsName)
		err := w.Write(rowData)
		if err != nil {
			log.Println("write row data csv file is error,", err.Error())
			return GenerateError("CSVFileErr", err.Error())
		}
	}
	return nil
}

// 清理临时文件（如导出文件）
func FileClean(filepath string) {
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[FileNotExist]", fileInfo.Name(), "is not exist")
			return
		}
		log.Println("[FileError]", err.Error())
		return
	}
	if fileInfo.IsDir() {
		log.Println("[Error]", fileInfo.Name(), "is not a file")
		return
	}
	err = os.Remove(filepath)
	if err != nil {
		log.Println("[RemoveFailed]", fileInfo.Name(), "remove occur a error", err.Error())
	}
	log.Println("[Completed]", fileInfo.Name(), "is cleaned up")
}

// 制造表头
func getHeadersData(mapData map[string]any) []string {
	var headers = make([]string, 0, len(mapData))
	for key := range mapData {
		headers = append(headers, key)
	}
	return headers
}

// 提取行数据成切片(当前行)
func getRowsData(record map[string]any, headers []string) []string {
	row := make([]string, 0, len(headers))
	for _, col := range headers {
		row = append(row, fmt.Sprintf("%v", record[col]))
	}
	return row
}
