package core

import (
	"fmt"
	"testing"
)

func TestParseSQL(T *testing.T) {
	sqlText := `EXPLAIN SELECT * FROM products WHERE price BETWEEN 100 AND 200;SELECT 
  u.department, 
  AVG(u.salary) AS avg_salary 
FROM users u 
GROUP BY u.department 
HAVING AVG(u.salary) > 10000;
`
	// sqlText := "select u1.id,u1.name from (select id,name from sql_demo.users where name='oceanwang' ) as u1 left join sql_demo.users u2 on u1.id = u2.id;"
	res, err := ParseV3(sqlText)
	if err != nil {
		fmt.Println("ERROR", err)
	}
	for _, p := range res {
		fmt.Println(p)
	}

}
