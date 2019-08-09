package LoginSignup

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var errduplicateEmail = errors.New("E-mail already exists")
var errInvalidEmail = errors.New("Invalid email please sign up")
var errInvalidToken = errors.New("Invalid Token")
var serverError = errors.New("Internal Server Error")
var errduplicateUserName = errors.New("duplicate user name please try with another")
var errinvalidLogin = errors.New("Invalid password for given email ")
var errorVerification = errors.New("User not verified please verify your email")
var errEmptyFields = errors.New("Empty fields Please fill the fields and try again")

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	s := new(Store)
	s.db = db
	return s
}

func (s *Store) StoreNewUser(u *User) error {
	if u.UserName == "" || u.EmailID == "" || u.Password == "" {
		return errEmptyFields
	}

	stmt, err := s.db.Prepare("Insert into users(email_id,user_name,password,is_verified) Values(?,?,?,?)")
	if err != nil {
		fmt.Printf("%v", err)
		return serverError
	}
	pass, _ := GenerateHash(u.Password)
	_, err = stmt.Exec(u.EmailID, u.UserName, pass, u.IsVerified)
	if err != nil {
		fmt.Printf("%v", err)
		if strings.Contains(err.Error(), "PRIMARY") {
			return errduplicateEmail
		}
		return errduplicateUserName
	}

	token := GenerateToken(u.EmailID)
	err = storeToken(s, u.UserName, token)
	if err != nil {
		return err
	}

	go SendMail(u.EmailID, token)

	return nil
}

func storeToken(s *Store, userName string, token string) error {
	stmt1, err := s.db.Prepare("Insert into tokens(user_name,token) Values(?,?)")
	if err != nil {
		fmt.Printf("%v", err)
		return serverError
	}
	_, err = stmt1.Exec(userName, token)
	if err != nil {
		fmt.Printf("%v", err)
		return serverError
	}
	return nil
}

func (s *Store) RegisterUser(token string) error {
	userName, err := verifyToken(s, token)
	if err != nil {
		return err
	}

	stmt, er := s.db.Prepare("UPDATE users SET is_verified=1 where user_name=?")
	if er != nil {
		fmt.Printf("%v", err)
		return serverError
	}
	_, er = stmt.Exec(userName)
	if er != nil {
		fmt.Printf("%v", err)
		return serverError
	}

	err = deleteToken(s, userName)
	if err != nil {
		return err
	}
	return nil
}
func verifyToken(s *Store, token string) (string, error) {
	userName := ""
	rows, err := s.db.Query("select user_name from tokens where token=?", token)
	if err != nil {
		fmt.Printf("%v", err)
		return "", serverError
	}
	defer rows.Close()
	rows.Next()
	err = rows.Scan(&userName)
	if err != nil {
		fmt.Printf("%v", err)
		return "", errInvalidToken
	}
	return userName, nil
}

func deleteToken(s *Store, userName string) error {
	_, err := s.db.Query("DELETE  From tokens where user_name=?", userName)
	if err != nil {
		fmt.Printf("%v", err)
		return serverError
	}
	return nil
}

func (s *Store) LogIn(email string, password string) (string, error) {
	if email == "" || password == "" {
		return "", errEmptyFields
	}

	err := checkVerifyStatus(s, email)
	if err != nil {
		return "", err
	}

	userName, err := validateDetails(s, email, password)
	if err != nil {
		return "", err
	}
	return userName, nil
}
func validateDetails(s *Store, email string, password string) (string, error) {
	userName := ""
	passHash := ""
	rows, err := s.db.Query("select user_name, password  from users where email_id=? ", email)
	if err != nil {
		fmt.Printf("%v", err)
		return "", serverError
	}
	defer rows.Close()

	rows.Next()
	er := rows.Scan(&userName, &passHash)
	if er != nil {
		fmt.Printf("%v", er)
		return "", serverError
	}
	err = bcrypt.CompareHashAndPassword([]byte(passHash), []byte(password))
	if err != nil {
		return "", errinvalidLogin
	}
	return userName, nil
}
func checkVerifyStatus(s *Store, email string) error {
	isVerified := -1
	rows, err := s.db.Query("select is_verified from users where email_id=?", email)
	if err != nil {
		fmt.Printf("%v", err)
		return serverError
	}
	defer rows.Close()

	rows.Next()
	er := rows.Scan(&isVerified)
	if er != nil {
		fmt.Printf("%v", err)
		return errInvalidEmail
	}
	if isVerified == 0 {
		return errorVerification
	}
	return nil
}

func (s *Store) StorePost(post *Posts) error {
	stmt, err := s.db.Prepare("insert into posts(user_name,post,time) Values(?,?,NOW())")
	if err != nil {
		fmt.Printf("%v", err)
		return serverError
	}
	_, err = stmt.Exec(post.UserName, post.Post)
	if err != nil {
		fmt.Printf("%v", err)
		return serverError
	}
	return nil
}
func (s *Store) RetrievePosts(userName string, sort string) ([]Posts, error) {
	switch sort {
	case "asc":
		return retrieveAscending(s, userName)
	default:
		return retrieveDescending(s, userName)
	}
}
func retrieveAscending(s *Store, userName string) ([]Posts, error) {
	var rows *sql.Rows
	var err error
	if userName == "" {
		rows, err = s.db.Query("select user_name , post from posts order by time ")
	} else {
		rows, err = s.db.Query("select user_name,post from posts  where user_name=? order by time", userName)
	}
	if err != nil {
		fmt.Printf("%v", err)
		return nil, serverError
	}
	defer rows.Close()
	return getDataFromRows(rows)
}
func retrieveDescending(s *Store, userName string) ([]Posts, error) {
	var rows *sql.Rows
	var err error
	if userName == "" {
		rows, err = s.db.Query("select user_name , post from posts order by time desc")
	} else {
		rows, err = s.db.Query("select user_name,post from posts  where user_name=? order by time desc ", userName)
	}
	if err != nil {
		fmt.Printf("%v", err)
		return nil, serverError
	}
	defer rows.Close()
	return getDataFromRows(rows)
}
func getDataFromRows(rows *sql.Rows) ([]Posts, error) {
	var data []Posts
	var post Posts
	for rows.Next() {
		err := rows.Scan(&post.UserName, &post.Post)
		if err != nil {
			fmt.Printf("%v", err)
			return nil, serverError
		}
		data = append(data, post)
	}
	return data, nil
}
