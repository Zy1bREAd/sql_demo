package core

import (
	"fmt"
	"testing"
)

func TestParseSQLFrom(T *testing.T) {
	sqlText := `SELECT u.name, o.order_id 
FROM users u 
JOIN orders o ON u.id = o.user_id OR u.email = o.user_email;SELECT 
  u.name, 
  o.order_id, 
  p.product_name 
FROM users u 
JOIN orders o ON u.id = o.user_id 
JOIN products p ON o.product_id = p.id;`
	// sqlText := "select u1.id,u1.name from (select id,name from sql_demo.users where name='oceanwang' ) as u1 left join sql_demo.users u2 on u1.id = u2.id;"
	res, err := ParseV3(sqlText)
	if err != nil {
		fmt.Println("ERROR", err)
	}
	for _, p := range res {
		fmt.Println(p)
	}

}
