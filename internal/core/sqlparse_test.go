package core

import (
	"fmt"
	"testing"
)

func TestParseSQL(T *testing.T) {
	sqlText := `SELECT e1.name, e1.dept_id, e1.salary
FROM employees e1
WHERE e1.salary = (
    SELECT MAX(e2.salary)
    FROM employees e2
    WHERE e2.dept_id = e1.dept_id
);
`
	// sqlText := "select u1.id,u1.name from (select id,name from sql_demo.users where name='oceanwang' ) as u1 left join sql_demo.users u2 on u1.id = u2.id;"
	res, err := ParseV3(sqlText)
	if err != nil {
		fmt.Println("ERROR", err)
	}
	for _, p := range res {
		fmt.Println(p.WhereExpr, p.HavingExpr)
	}

}
