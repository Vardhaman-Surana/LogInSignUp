package LoginSignup

type User struct {
	EmailID    string `json:"email"`
	UserName   string `json:"userName"`
	Password   string `json:"password"`
	IsVerified int
}

func NewUser(emailID string, userName string, password string) *User {
	return &User{
		EmailID:    emailID,
		UserName:   userName,
		Password:   password,
		IsVerified: 0,
	}
}
