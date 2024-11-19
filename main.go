package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/purisaurabh/api-encryption-decryption/helper"
)

type user struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("mysql", "mysql_user:mysql_user@tcp(127.0.0.1:3306)/encrypted_db")
	if err != nil {
		panic(err.Error())
	}
}

func insertUser(w http.ResponseWriter, r *http.Request) {
	var user user

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		fmt.Println("error in decoding request body: ", err)
		return
	}

	fmt.Println("username: ", user.Username)
	fmt.Println("email: ", user.Email)
	fmt.Println("password: ", user.Password)

	if user.Username == "" || user.Email == "" || user.Password == "" {
		fmt.Fprintf(w, "All fields are mandatory")
		return
	}

	userName, err := helper.Encrypt(user.Username)
	if err != nil {
		fmt.Println("error in encrypting username: ", err)
		return
	}

	userEmail, err := helper.Encrypt(user.Email)
	if err != nil {
		fmt.Println("error in encrypting email: ", err)
		return
	}

	userPassword, err := helper.Encrypt(user.Password)
	if err != nil {
		fmt.Println("error in encrypting password: ", err)
		return
	}

	fmt.Println("encrypted username: ", userName)
	fmt.Println("encrypted email: ", userEmail)
	fmt.Println("encrypted password: ", userPassword)

	result, err := db.Exec("INSERT INTO users(username, email, password) VALUES(?,?,?)", userName, userEmail, userPassword)
	if err != nil {
		fmt.Println("error in inserting record: ", err)
		return
	}

	id, _ := result.LastInsertId()
	fmt.Fprintf(w, "User with id: %d inserted successfully", id)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var username, email, password string
	err := db.QueryRow("SELECT username , email , password FROM users WHERE id = ?", id).Scan(&username, &email, &password)
	if err != nil {
		fmt.Println("error in fetching record: ", err)
		return
	}

	userName, err := helper.Decrypt(username)
	if err != nil {
		fmt.Println("error in decrypting username: ", err)
		return
	}

	userEmail, err := helper.Decrypt(email)
	if err != nil {
		fmt.Println("error in decrypting email: ", err)
		return
	}

	userPassword, err := helper.Decrypt(password)
	if err != nil {
		fmt.Println("error in decrypting password: ", err)
		return
	}

	fmt.Fprintf(w, "User with id: %s has username: %s, email: %s and password: %s", id, userName, userEmail, userPassword)
}

func main() {
	initDB()
	defer db.Close()
	fmt.Println("Successfully connected to database")
	r := mux.NewRouter()
	r.HandleFunc("/user", insertUser).Methods("POST")
	r.HandleFunc("/user/{id}", getUser).Methods("GET")
	fmt.Println("Server is running on port 8080")
	http.ListenAndServe(":8080", r)
}
