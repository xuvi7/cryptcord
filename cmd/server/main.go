package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"os"

	// "net/websocket"
	"github.com/coder/websocket"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

const (
	SESSION_TOKEN_LENGTH = 64
	SALT_LENGTH          = 16
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username"`
}

var db *sql.DB

/*
* API ENDPOINT HANDLER
* 1. check database for matching identity
* 2. create new database entry
* 3. create session token for user
* 4. send http response with session token as cookie
 */
func register(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	var requestData registerRequest
	json.Unmarshal(body, &requestData)
	uuid, err := registerUser(requestData.Email, requestData.Password, requestData.Username)
	response := make(map[string]string)
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(marshaledResponse)
		return
	}

	sessionToken := createSessionToken(uuid)
	setCookieHandler(w, sessionToken)

	w.Write([]byte("{}"))
}

/*
 * API ENDPOINT HANDLER
 * 1. check database for matching identity
 * 2. create session token for user
 * 3. send http response with session token as cookie
 */
func login(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}

	var requestData loginRequest
	json.Unmarshal(body, &requestData)
	uuid, err := loginUser(requestData.Email, requestData.Password)
	response := make(map[string]string)
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(marshaledResponse)
		return
	}

	sessionToken := createSessionToken(uuid)
	setCookieHandler(w, sessionToken)
	w.Write([]byte("{}"))
}

func handleWs(w http.ResponseWriter, req *http.Request) {
	c, err := websocket.Accept(w, req, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := c.CloseRead(req.Context())
	<-ctx.Done()
}

func createDatabase() {
	file, err := os.Create("database.db") // Create SQLite file
	if err != nil {
		log.Fatal(err.Error())
	}
	file.Close()
}

func registerUser(email string, password string, username string) (string, error) {
	if len(password) < 8 || len(username) < 3 {
		return "", errors.New("username must be longer than 3 characters and password must be 8 characters or more")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return "", errors.New("invalid email address")
	}
	uuid := uuid.New()
	salt := make([]byte, SALT_LENGTH)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	hashedPassword := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	// don't need to manually check duplicates due to SQL setup
	insertUserSQL := `INSERT INTO users (
		"uuid",		
		"email",
		"password",
		"username",
		"salt"
		) VALUES (?, ?, ?, ?, ?);`

	_, err = db.Exec(insertUserSQL, uuid.String(), email, hashedPassword, username, salt)
	if err != nil {
		return "", err
	}
	return uuid.String(), nil
}

func loginUser(email string, password string) (string, error) {
	getUserSQL := `SELECT uuid, password, salt FROM users WHERE email = ?`
	row := db.QueryRow(getUserSQL, email)
	var uuid string
	var hashedPwd []byte
	var salt []byte
	err := row.Scan(&uuid, &hashedPwd, &salt)
	if err != nil {
		return "", err
	}
	if bytes.Equal(hashedPwd, argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)) {
		return uuid, nil
	} else {
		return "", errors.New("incorrect password")
	}
}

func main() {
	http.Handle("/", http.FileServer(http.Dir("./public/auth/")))
	http.Handle("/chat", http.FileServer(http.Dir("./public/chat/")))
	http.HandleFunc("/api/login", login)
	http.HandleFunc("/api/register", register)
	http.HandleFunc("/ws", handleWs)

	setup := false
	if _, err := os.Stat("database.db"); errors.Is(err, os.ErrNotExist) {
		setup = true
		createDatabase()
	}

	db, _ = sql.Open("sqlite3", "./database.db") // Open the created SQLite File
	defer db.Close()
	if setup {
		createUserTableSQL := `CREATE TABLE users (
		"uuid" TEXT NOT NULL PRIMARY KEY,		
		"email" TEXT NOT NULL UNIQUE,
		"password" BLOB NOT NULL,
		"username" TEXT NOT NULL UNIQUE,
		"salt" BLOB NOT NULL
		);`

		_, err := db.Exec(createUserTableSQL)
		if err != nil {
			log.Fatal(err.Error())
		}

		createTokenTableSQL := `CREATE TABLE token (
			"uuid" TEXT NOT NULL PRIMARY KEY,		
			"token" TEXT NOT NULL UNIQUE
		);`

		_, err = db.Exec(createTokenTableSQL)
		if err != nil {
			log.Fatal(err.Error())
		}
	}

	// start server at end because of blocking
	err := http.ListenAndServe(":80", nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}

/*
 * generate new session token for uuid, empty string indicates an error
 */
func createSessionToken(uuid string) string {
	randomBytes := make([]byte, SESSION_TOKEN_LENGTH)
	if _, err := rand.Read(randomBytes); err != nil {
		return ""
	}
	// Encode to Base64 for URL-safe string
	token := base64.URLEncoding.EncodeToString(randomBytes)
	updateTokenSQL := "INSERT OR REPLACE INTO token (uuid, token) VALUES (?, ?)"

	_, err := db.Exec(updateTokenSQL, uuid, token)
	if err != nil {
		log.Fatal(err.Error())
	}

	return token
}

func setCookieHandler(w http.ResponseWriter, token string) {
	cookie := http.Cookie{
		Name:  "sessionToken",
		Value: token, // session token
	}

	http.SetCookie(w, &cookie)
}

// func getCookie(w http.ResponseWriter, r *http.Request) (string, error) {
// 	cookie, err := r.Cookie("sessionToken")
// 	if err != nil {
// 		switch {
// 		case errors.Is(err, http.ErrNoCookie):
// 			http.Error(w, "cookie not found", http.StatusBadRequest)
// 		default:
// 			log.Println(err)
// 			http.Error(w, "server error", http.StatusInternalServerError)
// 		}
// 		return "", err
// 	}

// 	return cookie.Value, nil
// }
