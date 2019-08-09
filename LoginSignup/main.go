package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"

	LoginSignup "github.com/vds/Assignments/LoginSignUpTDD"
)

func main() {
	DB, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/login_signup")
	defer DB.Close()
	if err != nil {
		log.Fatal("Cannot open database")
	}
	store := LoginSignup.NewStore(DB)
	Server := LoginSignup.NewUserServer(store)
	err = http.ListenAndServe(":8080", Server)
	if err != nil {
		fmt.Printf("%v", err)
	}
	DB.Close()
}
