package services

import (
	"context"
	"fmt"
	"testing"
)

func TestParseSQL(T *testing.T) {
	sqlText := `SELECT id, name FROM users WHERE user_type = 1 UNION SELECT id, name FROM admins WHERE status = 1;`
	// sqlText := "select u1.id,u1.name from (select id,name from sql_demo.users where name='oceanwang' ) as u1 left join sql_demo.users u2 on u1.id = u2.id;"
	res, err := ParseV3(context.Background(), sqlText)
	if err != nil {
		fmt.Println("ERROR", err)
	}

	// var reco func(*WhereParse)
	for _, p := range res {
		fmt.Println(p.Where)
	}
	// 	fmt.Println("debg print ", p.Where)
	// 	reco = func(w *WhereParse) {
	// 		if w == nil {
	// 			return
	// 		}
	// 		if !w.IsSimple {
	// 			reco(w.Left)
	// 			reco(w.Right)
	// 			reco(w.From)
	// 			reco(w.To)
	// 		}
	// 		fmt.Println("递归：", w.Expr)
	// 	}
	// 	reco(&p.Where)
	// }

}
