package LoginSignup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const emptyFieldsError = "Empty Fields Please Try Again Using appropriate values"
const errPostLength = "Post contains more than 255 characters"
const errEmptyPostField = "Empty post field please fill the field and try again"

var jwtKey = []byte("encryptionKey")

type DataStore interface {
	StoreNewUser(u *User) error
	RegisterUser(token string) error
	LogIn(email string, password string) (string, error)
	StorePost(post *Posts) error
	RetrievePosts(userName string, sort string) ([]Posts, error)
}

type UserServer struct {
	store DataStore
	http.Handler
}
type Posts struct {
	UserName string `json:"UserName"`
	Post     string `json:"Post"`
}

type Filter struct {
	UserName string `json:"UserName"`
	Sort     string `json:"Sort"`
}
type Message struct {
	Message string `json:"msg"`
}

func NewUserServer(store DataStore) *UserServer {
	u := new(UserServer)
	u.store = store

	router := http.NewServeMux()
	router.Handle("/register", http.HandlerFunc(u.registerHandler))
	router.Handle("/confirm/", http.HandlerFunc(u.confirmHandler))
	router.Handle("/login", http.HandlerFunc(u.loginHandler))
	router.Handle("/post", u.authMiddleware(http.HandlerFunc(u.postHandler)))
	router.Handle("/post/retrieve", http.HandlerFunc(u.postRetrieveHandler))

	u.Handler = router
	return u
}

func (u *UserServer) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	user := &User{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("%v", err)
		return
	}
	err = u.store.StoreNewUser(user)
	status := http.StatusInternalServerError
	if err != nil {
		switch err {
		case errEmptyFields:
			status = http.StatusBadRequest
		case errduplicateUserName, errduplicateEmail:
			status = http.StatusNotAcceptable
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Write([]byte("Verification mail sent please verify your mail to login"))
	w.WriteHeader(http.StatusOK)
}

func (u *UserServer) confirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	msg := &Message{}
	token := strings.TrimPrefix(r.URL.Path, "/confirm/")
	err := u.store.RegisterUser(token)
	status := http.StatusInternalServerError
	if err != nil {
		if err == errInvalidToken {
			status = http.StatusBadRequest
			msg.Message = err.Error()
		}
		data, er := json.Marshal(msg)
		if er != nil {
			fmt.Print(er)
		}
		w.Write([]byte(data))
		w.WriteHeader(status)
		return
	}
	message := &Message{}
	message.Message = "Registration Successful"
	msgData, er := json.Marshal(message)
	if er != nil {
		fmt.Print(er)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write([]byte(msgData))
	w.WriteHeader(status)
}

func (u *UserServer) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user := &User{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("%v", err)
		return
	}
	username, err := u.store.LogIn(user.EmailID, user.Password)
	status := http.StatusInternalServerError
	if err != nil {
		switch err {
		case errInvalidEmail, errorVerification, errinvalidLogin:
			status = http.StatusUnauthorized
		case errEmptyFields:
			status = http.StatusUnauthorized
		}
		http.Error(w, err.Error(), status)
		return
	}
	var expirationTime = time.Now().Add(15 * time.Minute)
	claims := Claims{
		UserName: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("token", tokenString)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "LogIn Successful")
}

func (u *UserServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("token")
		tknStr := string(value)
		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if strings.Contains(err.Error(), "expired") {
				fmt.Fprint(w, "Token expired please login again")
			}
			fmt.Printf("%v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "userName", claims.UserName)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (u *UserServer) postHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	post := &Posts{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(post)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		panic(err)
	}
	post.UserName = r.Context().Value("userName").(string)
	if len(post.Post) > 255 {
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte(errPostLength))
		return
	}
	if len(post.Post) == 0 {
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte(errEmptyPostField))
		return
	}
	err = u.store.StorePost(post)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "post stored")
}

func (u *UserServer) postRetrieveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	userName := r.URL.Query().Get("UserName")
	sort := r.URL.Query().Get("Sort")

	dataPosts, err := u.store.RetrievePosts(userName, sort)
	status := http.StatusInternalServerError
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	if dataPosts == nil {
		w.Header().Add("Content-Type", "application/json")
		w.Write([]byte(`[]`))
		return
	}
	data, err := json.Marshal(dataPosts)
	if err != nil {
		http.Error(w, serverError.Error(), http.StatusInternalServerError)
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte(data))
}
