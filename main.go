package main

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	a, _ := gormadapter.NewAdapter("mysql", "root:123456@tcp(127.0.0.1:3306)/casbin", true) // Your driver and data source.
	e, _ := casbin.NewEnforcer("./rbac_model.conf", a)

	// Load the policy from DB.
	e.LoadPolicy()

	// add policy
	rules := [][]string{
		[]string{"data1_admin", "data1", "*", "allow"},
		[]string{"data2_admin", "data2", "*", "allow"},
		[]string{"read_admin", "*", "get", "allow"},
		[]string{"write_admin", "*", "post", "allow"},
		[]string{"admin", "*", "*", "allow"},
		[]string{"tom", "data1", "post", "deny"},
	}

	areRulesAdded, err := e.AddPolicies(rules)
	if err != nil {
		fmt.Println("Policies areRulesAdded: ", err)
		return
	}
	fmt.Println("Policies areRulesAdded: ", areRulesAdded)

	e.AddPolicy("ham", "data2", "get", "deny")
	e.RemovePolicy("ham", "data2", "get", "deny")

	// add group role
	gRules := [][]string{
		[]string{"ham", "data1_admin"},
		[]string{"jack", "data2_admin"},
		[]string{"tom", "read_admin"},
		[]string{"sam", "write_admin"},
		[]string{"toby", "admin"},
	}

	areGRulesAdded, err := e.AddGroupingPolicies(gRules)
	if err != nil {
		fmt.Println("GroupingPolicies areRulesAdded: ", err)
		return
	}
	fmt.Println("GroupingPolicies areRulesAdded: ", areGRulesAdded)

	// check
	checks := [][]interface{}{
		// data1_admin
		{"ham", "data1", "get"},  //true
		{"ham", "data1", "post"}, //true
		{"ham", "data2", "get"},  //false
		{"ham", "data2", "post"}, //false

		// data2_admin
		{"jack", "data1", "get"},  //false
		{"jack", "data1", "post"}, //false
		{"jack", "data2", "get"},  //true
		{"jack", "data2", "post"}, //true

		// read_admin
		{"tom", "data1", "get"},  //true
		{"tom", "data1", "post"}, //false
		{"tom", "data2", "get"},  //true
		{"tom", "data2", "post"}, //false

		// write_admin
		{"sam", "data1", "get"},  //false
		{"sam", "data1", "post"}, //true
		{"sam", "data2", "get"},  //false
		{"sam", "data2", "post"}, //true

		// admin
		{"toby", "data1", "get"},  //true
		{"toby", "data1", "post"}, //true
		{"toby", "data2", "get"},  //true
		{"toby", "data2", "post"}, //true
	}
	oks, err := e.BatchEnforce(checks)
	if err != nil {
		fmt.Println("BatchEnforce error: ", err)
		return
	}
	fmt.Println(oks)

	// ok, err = e.Enforce("tom", "data2", "write")
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// fmt.Println("tom can write data2: ", ok)

	ps := e.GetPolicy()
	fmt.Println(ps)

}
