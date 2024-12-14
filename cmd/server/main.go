package main

import (
	"bytes"
	"context"
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
	"strconv"
	"sync"

	"time"

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

type userRequest struct {
	Type string `json:"type"` // types are: message, edit, delete, chanelSub, channelAdd, channelDelete
	Arg1 string `json:"arg1"`
	Arg2 string `json:"arg2,omitempty"`
}

type Message struct {
	MessageId string    `json:"messageId"`
	Timestamp time.Time `json:"timestamp"`
	//	ChannelID string    `json:"channelId"`
	Username string `json:"username"`
	Message  string `json:"message"`
}

type Channel struct {
	ChannelID   string `json:"channelId"`
	ChannelName string `json:"channelName"`
}

type User struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
}

var db *sql.DB
var tokens sync.Map // maps token to user ID
var userConnMutex sync.Mutex
var userConnections map[string]*websocket.Conn // maps user ID to websocket connection

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
	token := req.PathValue("token")
	uidAny, ok := tokens.Load(token)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("{\"error\": \"Invalid authentication token supplied\"}"))
		return
	}
	userID := uidAny.(string)
	c, err := websocket.Accept(w, req, nil)
	if err != nil {
		return
	}
	userConnections[userID] = c
	go func() {
		for {
			_, msg, err := c.Read(context.Background())
			if err != nil {
				return
			}
			var userReq userRequest
			parseErr := json.Unmarshal(msg, &userReq)
			if parseErr != nil {
				continue
			}

			switch userReq.Type {
			case "message":
				if userReq.Arg2 == "" {
					err = fmt.Errorf("missing message content")
					break
				}
				err = createMessage(userID, userReq.Arg1, userReq.Arg2)
			case "edit":
				if userReq.Arg2 == "" {
					err = fmt.Errorf("missing message content")
					break
				}
				err = editMessage(userID, userReq.Arg1, userReq.Arg2)
			case "delete":
				err = deleteMessage(userID, userReq.Arg1)
			case "channelSub":
				err = subscribeToChannel(userID, userReq.Arg1, userReq.Arg2)
			case "channelAdd":
				err = createChannel(userID, userReq.Arg1)
			case "channelDelete":
				err = deleteChannel(userID, userReq.Arg1)
			default:
				continue
			}

			ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*5)
			response := make(map[string]string)
			if err != nil {
				response["result"] = "error"
				response["message"] = err.Error()
				marshaledResponse, _ := json.Marshal(response)
				c.Write(ctx, websocket.MessageText, marshaledResponse)
			}
			cancelFunc()
		}
	}()
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

func createMessage(userUuid string, channelId string, content string) error {
	//* verify that uuid is subscribed to channel
	verifyMembershipSQL := "SELECT 1 FROM membership WHERE channelUuid = ? AND userUuid = ?;"

	val := db.QueryRow(verifyMembershipSQL, channelId, userUuid)
	exists := 1
	err := val.Scan(&exists)
	if err != nil {
		return err
	}

	messageId := uuid.New().String()

	addMessageSQL := `INSERT INTO messages ("msgUuid", "timestamp", "channelUuid", "userUuid", "msg") VALUES (?, ?, ?, ?, ?);`
	curTime := time.Now()
	_, err = db.Exec(addMessageSQL, messageId, curTime, channelId, userUuid, content)
	if err != nil {
		return err
	}

	username, err := findUsername(userUuid)
	if err != nil {
		log.Fatalf("Inconsistent database state: username not found for uuid %s", userUuid)
	}
	updateUsers("message", channelId, messageId, username, strconv.FormatInt(curTime.UnixNano(), 10), content)

	//go sendMessage(messageId)
	return nil
}

func editMessage(userUuid string, messageId string, content string) error {
	verifyOwnershipSQL := "SELECT 1 FROM messages WHERE userUuid = ? AND msgUuid = ?;"

	val := db.QueryRow(verifyOwnershipSQL, userUuid, messageId)
	exists := 1
	err := val.Scan(&exists)
	if err != nil {
		return err
	}

	editMessageSQL := `UPDATE messages SET msg = ? WHERE msgUuid = ?;`
	_, err = db.Exec(editMessageSQL, content, messageId)
	if err != nil {
		return err
	}

	channelId, err := findChannelId(messageId)
	if err != nil {
		return err
	}

	updateUsers("edit", channelId, messageId, content)

	return nil
}

func deleteMessage(userUuid string, messageId string) error {
	//* verify that uuid wrote the message
	verifyOwnershipSQL := "SELECT 1 FROM messages WHERE userUuid = ? AND msgUuid = ?;"

	val := db.QueryRow(verifyOwnershipSQL, userUuid, messageId)
	exists := 1
	err := val.Scan(&exists)
	if err != nil {
		return err
	}

	channelId, err := findChannelId(messageId)
	if err != nil {
		return err
	}

	deleteMessageSQL := `DELETE FROM messages WHERE msgUuid = ?;`
	_, err = db.Exec(deleteMessageSQL, messageId)
	if err != nil {
		return err
	}

	updateUsers("delete", channelId, messageId)

	return nil
}

func subscribeToChannel(userUuid string, channelId string, userToBeSubscribed string) error {
	verifyMembershipSQL := "SELECT 1 FROM membership WHERE channelUuid = ? AND userUuid = ?;"

	val := db.QueryRow(verifyMembershipSQL, channelId, userUuid)
	exists := 1
	err := val.Scan(&exists)
	if err != nil {
		return err
	}

	updateMembershipSQL := "INSERT OR REPLACE INTO membership (channelUuid, userUuid) VALUES (?, ?);"

	_, err = db.Exec(updateMembershipSQL, channelId, userToBeSubscribed)
	if err != nil {
		return err
	}

	username, err := findUsername(userToBeSubscribed)
	if err != nil {
		return err
	}

	updateUsers("subscribe", channelId, username)

	return nil
}

func createChannel(userUuid string, name string) error {
	createChannelSQL := `INSERT INTO channels (
			"uuid",
			"owner",
			"name"
		) VALUES (?, ?, ?);`

	channelUuid := uuid.New().String()
	_, err := db.Exec(createChannelSQL, channelUuid, userUuid, name)
	if err != nil {
		return err
	}

	insertMembershipSQL := `INSERT INTO membership (
			"channelUuid",
			"userUuid"
		) VALUES (?, ?);`

	_, err = db.Exec(insertMembershipSQL, channelUuid, userUuid)
	if err != nil {
		return err
	}

	username, err := findUsername(userUuid)
	if err != nil {
		return err
	}

	updateUsers("createChannel", channelUuid, username, name)

	return nil
}

func deleteChannel(userUuid string, channelId string) error {
	//* verify that uuid created the channel
	verifyOwnershipSQL := "SELECT 1 FROM channels WHERE uuid = ? AND owner = ?;"

	val := db.QueryRow(verifyOwnershipSQL, channelId, userUuid)
	exists := 1
	err := val.Scan(&exists)
	if err != nil {
		return err
	}

	deleteChannelSQL := "DELETE FROM channels WHERE uuid = ?;"
	_, err = db.Exec(deleteChannelSQL, channelId)
	if err != nil {
		return err
	}

	deleteMembershipSQL := "DELETE FROM membership WHERE channelUuid = ?;"
	_, err = db.Exec(deleteMembershipSQL, channelId)
	if err != nil {
		return err
	}

	deleteMessagesSQL := "DELETE FROM messages WHERE channelUuid = ?;"
	_, err = db.Exec(deleteMessagesSQL, channelId)
	if err != nil {
		return err
	}

	updateUsers("deleteChannel", channelId)
	return nil
}

func findChannelId(messageId string) (string, error) {
	findChannelSQL := "SELECT channelUuid FROM messages WHERE msgUuid = ?;"
	val := db.QueryRow(findChannelSQL, messageId)
	channelId := ""
	err := val.Scan(&channelId)
	if err != nil {
		return "", err
	}
	return channelId, nil
}

func findChannelName(channelId string) (string, error) {
	channelNameSQL := "SELECT name FROM channels WHERE uuid = ?;"
	val := db.QueryRow(channelNameSQL, channelId)
	channelName := ""
	err := val.Scan(&channelName)
	if err != nil {
		return "", err
	}
	return channelName, nil
}

func findUsername(userId string) (string, error) {
	findUsernameSQL := "SELECT username FROM users WHERE uuid = ?;"
	val := db.QueryRow(findUsernameSQL, userId)
	username := ""
	err := val.Scan(&username)
	if err != nil {
		return "", err
	}
	return username, nil
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
	tokens.Store(token, uuid)

	return token
}

func setCookieHandler(w http.ResponseWriter, token string) {
	cookie := http.Cookie{
		Name:     "sessionToken",
		Value:    token, // session token
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}

	http.SetCookie(w, &cookie)
}

/*
 * message args: messageId,username,time,content;
 * edit args: messageId,content;
 * delete args: messageId;
 * subscribe args: username;
 * createChannel args: username;
 * deleteChannel args: null;
 */
func updateUsers(action string, channelId string, args ...string) {
	response := make(map[string]string)
	response["action"] = action
	response["channelId"] = channelId
	for counter := 1; counter <= len(args); counter++ {
		response["arg"+strconv.Itoa(counter)] = args[counter-1]
	}
	marshaledResponse, _ := json.Marshal(response)

	channelUsersSQL := "SELECT userUuid FROM membership WHERE channelUuid = ?;"
	rows, err := db.Query(channelUsersSQL, channelId)
	if err != nil {
		return
	}
	defer rows.Close()
	userConnMutex.Lock()
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return
		}

		ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*5)
		if conn := userConnections[userID]; conn != nil {
			conn.Write(ctx, websocket.MessageText, marshaledResponse)
		}
		cancelFunc()
	}
	userConnMutex.Unlock()
}

func getCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	cookie, err := r.Cookie("sessionToken")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "cookie not found", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return "", err
	}

	return cookie.Value, nil
}

func getDataHandler(w http.ResponseWriter, req *http.Request) {
	authToken, err := getCookie(w, req)
	if err != nil {
		return
	}
	uuidAny, ok := tokens.Load(authToken)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("{\"error\": \"Invalid authentication token supplied\"}"))
		return
	}
	userID := uuidAny.(string)

	getChannelsSQL := "SELECT uuid, name FROM channels WHERE uuid IN (SELECT channelUuid FROM membership WHERE userUuid = ?)"
	getMessagesSQL := `SELECT msgUuid, timestamp, channelUuid, username, msg FROM messages INNER JOIN users ON messages.userUuid = users.uuid
	WHERE channelUuid IN (SELECT channelUuid FROM membership WHERE userUuid = ?);`
	getUsersSQL := `SELECT userUuid, channelUuid, username FROM membership INNER JOIN users ON membership.userUuid = users.uuid
	WHERE channelUuid IN (SELECT channelUuid FROM membership WHERE userUuid = ?)`

	transaction, err := db.Begin()
	if err != nil {
		return
	}
	defer transaction.Commit()
	channelsQuery, err1 := transaction.Query(getChannelsSQL, userID)
	messagesQuery, err2 := transaction.Query(getMessagesSQL, userID)
	usersQuery, err3 := transaction.Query(getUsersSQL, userID)
	if err1 != nil || err2 != nil || err3 != nil {
		return
	}

	response := make(map[string]interface{})
	channels := make([]Channel, 0)
	messages := make(map[string][]Message)
	users := make(map[string][]User)

	for channelsQuery.Next() {
		var channelId string
		var channelName string
		if err := channelsQuery.Scan(&channelId, &channelName); err != nil {
			return
		}
		channels = append(channels, Channel{channelId, channelName})
	}
	for messagesQuery.Next() {
		var messageId string
		var timestamp time.Time
		var channelId string
		var username string
		var message string
		if err := messagesQuery.Scan(&messageId, &timestamp, &channelId, &username, &message); err != nil {
			return
		}
		if messages[channelId] == nil {
			messages[channelId] = []Message{{messageId, timestamp /*, channelId*/, username, message}}
		} else {
			messages[channelId] = append(messages[channelId], Message{messageId, timestamp /*, channelId*/, username, message})
		}
	}
	for usersQuery.Next() {
		var userUuid string
		var channelId string
		var username string
		if err := usersQuery.Scan(&userUuid, &channelId, &username); err != nil {
			return
		}
		if users[channelId] == nil {
			users[channelId] = []User{{userUuid, username}}
		} else {
			users[channelId] = append(users[channelId], User{userUuid, username})
		}
	}

	response["result"] = "success"
	response["channels"] = channels
	response["messages"] = messages
	response["users"] = users

	marshaledResponse, _ := json.Marshal(response)
	w.Write(marshaledResponse)
}

func main() {
	userConnections = make(map[string]*websocket.Conn)
	http.Handle("/", http.FileServer(http.Dir("./public/auth/")))
	http.Handle("/chat/", http.FileServer(http.Dir("./public/")))
	http.HandleFunc("/api/login", login)
	http.HandleFunc("/api/register", register)
	http.HandleFunc("/api/getData", getDataHandler)
	http.HandleFunc("/ws/{token}", handleWs)

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

		createChannelsTableSQL := `CREATE TABLE channels (
			"uuid" TEXT NOT NULL PRIMARY KEY,
			"owner" TEXT NOT NULL,
			"name" TEXT NOT NULL
		);`

		_, err = db.Exec(createChannelsTableSQL)
		if err != nil {
			log.Fatal(err.Error())
		}

		createMembershipTableSQL := `CREATE TABLE membership (
			"channelUuid" TEXT NOT NULL,		
			"userUuid" TEXT NOT NULL,
			UNIQUE("channelUuid", "userUuid")
		);`

		_, err = db.Exec(createMembershipTableSQL)
		if err != nil {
			log.Fatal(err.Error())
		}

		createMessagesTableSQL := `CREATE TABLE messages (
			"msgUuid" TEXT NOT NULL PRIMARY KEY,
			"timestamp" DATETIME NOT NULL,
			"channelUuid" TEXT NOT NULL,		
			"userUuid" TEXT NOT NULL,
			"msg" TEXT NOT NULL
		);`

		_, err = db.Exec(createMessagesTableSQL)
		if err != nil {
			log.Fatal(err.Error())
		}
	}

	//* populate local channels

	// start server at end because of blocking
	err := http.ListenAndServe(":8080", nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
