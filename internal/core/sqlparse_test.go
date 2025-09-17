package core

import (
	"fmt"
	"testing"
)

func TestParseSQL(T *testing.T) {
	sqlText := `SELECT 
    c.customer_name,
    o_summary.total_orders,
    o_summary.avg_amount
FROM customers c
JOIN (
    SELECT 
        customer_id,
        COUNT(*) AS total_orders,
        AVG(order_amount) AS avg_amount
    FROM orders
    WHERE order_date >= '2024-01-01'
    GROUP BY customer_id
) o_summary ON c.customer_id = o_summary.customer_id
WHERE c.status = 'active';
`
	// sqlText := "select u1.id,u1.name from (select id,name from sql_demo.users where name='oceanwang' ) as u1 left join sql_demo.users u2 on u1.id = u2.id;"
	res, err := ParseV3(sqlText)
	if err != nil {
		fmt.Println("ERROR", err)
	}
	for _, p := range res {
		fmt.Println(p.From)
	}

}
