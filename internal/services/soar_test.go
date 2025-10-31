package services

import (
	"fmt"
	"log"
	"testing"
)

func TestSoarAnalysis(t *testing.T) {
	sql := `
		select id,search_word,search_type,CONVERT(result USING utf8),result_reg_id,
		create_time 
						from 
enterprise.t_tianyancha_search_log where search_word in ('王涛','高辉') 
order by create_time desc limit 10;

SELECT * FROM usm.t_parameter_type WHERE syscode BETWEEN 10000 AND 20000  ORDER BY CAST(syscode as SIGNED) DESC LIMIT 20;
	`
	soar := NewSoarAnalyzer(WithCommand("soar.linux-amd64_v11"), WithCommandPath("/tmp"), WithReportFormat("json"), WithSQLContent(sql))
	res, err := soar.Analysis()
	if err != nil {
		log.Println(err.Error())
	}
	fmt.Println(string(res))
}
