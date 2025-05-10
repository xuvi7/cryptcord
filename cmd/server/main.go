package main

import (
	// "bytes"
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
	// "golang.org/x/crypto/argon2"
)

const (
	SESSION_TOKEN_LENGTH = 64
	SALT_LENGTH          = 16
)

type authenticateRequest struct {
	Email       string `json:"email"`
	SecretValue string `json:"secret"`
}

type loginRequest struct {
	Email string `json:"email"`
}

type registerRequest struct {
	Email               string `json:"email"`
	Username            string `json:"username"`
	EncryptedPrivateKey string `json:"privateKey"`
	PublicKey           string `json:"publicKey"`
	Salt                string `json:"salt"`
	IV                  string `json:"iv"`
}

type keyRequest struct {
	Username string `json:"username"`
}

type userRequest struct {
	Type string `json:"type"` // types are: message, edit, delete, chanelSub, channelAdd, channelDelete
	Arg1 string `json:"arg1"`
	Arg2 string `json:"arg2,omitempty"`
	Arg3 string `json:"arg3,omitempty"`
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
	Key         string `json:"key"`
}

type User struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
}

var db *sql.DB
var tokens sync.Map // maps token to user ID
var userConnMutex sync.Mutex
var userConnections map[string]*websocket.Conn // maps user ID to websocket connection
var secrets sync.Map                           // maps user ID to current secret value if in authentication process

/*
* API ENDPOINT HANDLER
* 1. check database for matching identity
* 2. create new database entry
* 3. generate secret for user to authenticate with
 */
func handleRegister(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	var requestData registerRequest
	json.Unmarshal(body, &requestData)
	uuid, err := registerUser(requestData.Email, requestData.Username, requestData.EncryptedPrivateKey, requestData.PublicKey, requestData.Salt, requestData.IV)
	response := make(map[string]string)
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(marshaledResponse)
		return
	}

	secret, err := generateCode()
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(marshaledResponse)
		return
	}
	secrets.Store(uuid, secret)
	encryptedSecret, err := encrypt(requestData.PublicKey, secret)
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(marshaledResponse)
		return
	}

	response["secret"] = encryptedSecret
	marshaledResponse, _ := json.Marshal(response)
	w.Write(marshaledResponse)
}

/*
 * API ENDPOINT HANDLER
 * 1. check database for matching identity
 * 2. generate secret for user to authenticate with
 */
func handleLoginRequest(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}

	var requestData loginRequest
	json.Unmarshal(body, &requestData)
	salt, publicKey, encryptedPrivateKey, uuid, iv, err := getUserLoginData(requestData.Email)
	response := make(map[string]string)
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(marshaledResponse)
		return
	}
	secret, err := generateCode()
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(marshaledResponse)
		return
	}
	secrets.Store(uuid, secret)
	encryptedSecret, err := encrypt(publicKey, secret)
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(marshaledResponse)
		return
	}

	response["salt"] = salt
	response["publicKey"] = publicKey
	response["encryptedPrivateKey"] = encryptedPrivateKey
	response["iv"] = iv
	response["secret"] = encryptedSecret
	marshaledResponse, _ := json.Marshal(response)
	w.Write(marshaledResponse)
}

/*
 * API ENDPOINT HANDLER
 * 1. verify user possesses private key
 * 2. generate session token for user
 * 3. send http response with session token as cookie
 */
func handleAuthenticate(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}

	var requestData authenticateRequest
	json.Unmarshal(body, &requestData)
	response := make(map[string]string)

	uuid, err := getUuid(requestData.Email)
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(marshaledResponse)
		return
	}

	secret, ok := secrets.Load(uuid)
	if !ok {
		response["error"] = "could not authenticate, please try again"
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(marshaledResponse)
		return
	}

	if requestData.SecretValue != secret {
		response["error"] = "incorrect value, unable to authenticate"
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(marshaledResponse)
		return
	}

	sessionToken := createSessionToken(uuid)
	setCookieHandler(w, sessionToken)
	w.Write([]byte("{}"))
}

/*
 * API ENDPOINT HANDLER
 * returns public key for whatever user was passed in
 */
func handleKeyRequest(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	var requestData keyRequest
	json.Unmarshal(body, &requestData)
	publicKey, err := getUserPKey(requestData.Username)
	response := make(map[string]string)
	if err != nil {
		response["error"] = err.Error()
		marshaledResponse, _ := json.Marshal(response)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(marshaledResponse)
		return
	}

	response["publicKey"] = publicKey
	marshaledResponse, _ := json.Marshal(response)
	w.Write(marshaledResponse)
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
				err = subscribeToChannel(userID, userReq.Arg1, userReq.Arg2, userReq.Arg3)
			case "channelAdd":
				err = createChannel(userID, userReq.Arg1, userReq.Arg2)
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

func registerUser(email string, username string, encryptedPrivateKey string, publicKey string, salt string, iv string) (string, error) {
	if len(username) < 3 {
		return "", errors.New("username must be longer than 3 characters")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return "", errors.New("invalid email address")
	}
	uuid := uuid.New()
	// don't need to manually check duplicates due to SQL setup
	insertUserSQL := `INSERT INTO users (
		"uuid",		
		"email",
		"username",
		"encryptedPrivateKey",
		"publicKey",
		"salt",
		"iv"
		) VALUES (?, ?, ?, ?, ?, ?, ?);`

	_, err := db.Exec(insertUserSQL, uuid.String(), email, username, encryptedPrivateKey, publicKey, salt, iv)
	if err != nil {
		return "", err
	}
	return uuid.String(), nil
}

func getUuid(email string) (string, error) {
	getUserSQL := `SELECT uuid FROM users WHERE email = ?`
	row := db.QueryRow(getUserSQL, email)
	var uuid string
	err := row.Scan(&uuid)
	if err != nil {
		return "", err
	}
	return uuid, nil
}

func generateCode() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return encode(b), nil
}

func getUserLoginData(email string) (string, string, string, string, string, error) {
	if _, err := mail.ParseAddress(email); err != nil {
		return "", "", "", "", "", errors.New("invalid email address")
	}

	findDataSQL := `SELECT salt, publicKey, encryptedPrivateKey, uuid, iv FROM users WHERE email = ?`
	val := db.QueryRow(findDataSQL, email)
	salt := ""
	publicKey := ""
	encryptedPrivateKey := ""
	uuid := ""
	iv := ""
	err := val.Scan(&salt, &publicKey, &encryptedPrivateKey, &uuid, &iv)
	if err != nil {
		return "", "", "", "", "", err
	}
	return salt, publicKey, encryptedPrivateKey, uuid, iv, nil
}

func getUserPKey(username string) (string, error) {
	getUserSQL := `SELECT publicKey FROM users WHERE username = ?`
	row := db.QueryRow(getUserSQL, username)
	var key string
	err := row.Scan(&username, &key)
	if err != nil {
		return "", err
	}
	return key, nil
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

func subscribeToChannel(userUuid string, channelId string, userToBeSubscribed string, encryptedKey string) error {
	verifyMembershipSQL := "SELECT 1 FROM membership WHERE channelUuid = ? AND userUuid = ?;"

	val := db.QueryRow(verifyMembershipSQL, channelId, userUuid)
	exists := 1
	err := val.Scan(&exists)
	if err != nil {
		return err
	}

	getUserIDSQL := "SELECT uuid FROM users WHERE username = ?;"
	userIDQuery := db.QueryRow(getUserIDSQL, userToBeSubscribed)
	var userID string
	err = userIDQuery.Scan(&userID)
	if err != nil {
		return err
	}
	updateMembershipSQL := "INSERT INTO membership (channelUuid, userUuid, encryptedKey) VALUES (?, ?, ?);"
	_, err = db.Exec(updateMembershipSQL, channelId, userID, encryptedKey)
	if err != nil {
		return err
	}

	updateUsers("subscribe", channelId, userToBeSubscribed, encryptedKey)

	return nil
}

func createChannel(userUuid string, name string, encryptedKey string) error {
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
			"userUuid",
			"encryptedKey"
		) VALUES (?, ?, ?);`

	_, err = db.Exec(insertMembershipSQL, channelUuid, userUuid, encryptedKey)
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

	updateUsers("deleteChannel", channelId)
	transaction, transErr := db.Begin()
	if transErr != nil {
		return transErr
	}
	defer transaction.Commit()
	deleteChannelSQL := "DELETE FROM channels WHERE uuid = ?;"
	_, err = transaction.Exec(deleteChannelSQL, channelId)
	if err != nil {
		return err
	}

	deleteMembershipSQL := "DELETE FROM membership WHERE channelUuid = ?;"
	_, err = transaction.Exec(deleteMembershipSQL, channelId)
	if err != nil {
		return err
	}

	deleteMessagesSQL := "DELETE FROM messages WHERE channelUuid = ?;"
	_, err = transaction.Exec(deleteMessagesSQL, channelId)
	if err != nil {
		return err
	}

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
func updateUsers(action string, channelId string, args ...any) {
	response := make(map[string]interface{})
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

func handleGetData(w http.ResponseWriter, req *http.Request) {
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

	getChannelsSQL := `SELECT uuid, name, encryptedKey FROM channels INNER JOIN membership ON (channels.uuid = membership.channelUuid AND membership.userUuid = ?)
	WHERE uuid IN (SELECT channelUuid FROM membership WHERE userUuid = ?)`
	getMessagesSQL := `SELECT msgUuid, timestamp, channelUuid, username, msg FROM messages INNER JOIN users ON messages.userUuid = users.uuid
	WHERE channelUuid IN (SELECT channelUuid FROM membership WHERE userUuid = ?);`
	getUsersSQL := `SELECT userUuid, channelUuid, username FROM membership INNER JOIN users ON membership.userUuid = users.uuid
	WHERE channelUuid IN (SELECT channelUuid FROM membership WHERE userUuid = ?)`
	// getKeysSQL := `SELECT channelUuid, encryptedKey FROM membership WHERE userUuid userUuid = ?`
	getUsernameSQL := `SELECT username FROM users WHERE uuid = ?;`

	transaction, err := db.Begin()
	if err != nil {
		return
	}
	defer transaction.Commit()
	channelsQuery, err1 := transaction.Query(getChannelsSQL, userID, userID)
	messagesQuery, err2 := transaction.Query(getMessagesSQL, userID)
	usersQuery, err3 := transaction.Query(getUsersSQL, userID)
	usernameQuery := transaction.QueryRow(getUsernameSQL, userID)
	var currentUsername string
	err4 := usernameQuery.Scan(&currentUsername)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return
	}

	response := make(map[string]interface{})
	channels := make([]Channel, 0)
	messages := make(map[string][]Message)
	users := make(map[string][]User)

	for channelsQuery.Next() {
		var channelId string
		var channelName string
		var key string
		if err := channelsQuery.Scan(&channelId, &channelName, &key); err != nil {
			return
		}
		channels = append(channels, Channel{channelId, channelName, key})
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
	response["username"] = currentUsername
	response["channels"] = channels
	response["messages"] = messages
	response["users"] = users

	marshaledResponse, _ := json.Marshal(response)
	w.Write(marshaledResponse)
}

func handleGetChannelData(w http.ResponseWriter, req *http.Request) {
	channelID := req.PathValue("channelID")
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

	membershipSQL := "SELECT 1 FROM membership WHERE userUuid = ? AND channelUuid = ?;"
	getMessagesSQL := `SELECT msgUuid, timestamp, username, msg FROM messages INNER JOIN users ON messages.userUuid = users.uuid
	WHERE channelUuid = ?;`
	getUsersSQL := `SELECT userUuid, username FROM membership INNER JOIN users ON membership.userUuid = users.uuid
	WHERE channelUuid = ?;`
	getChannelInfoSQL := `SELECT name, encryptedKey FROM channels INNER JOIN membership ON (channels.uuid = membership.channelUuid AND membership.userUuid = ?) WHERE channels.uuid = ?;`

	transaction, err := db.Begin()
	if err != nil {
		return
	}
	defer transaction.Commit()
	membershipQuery := transaction.QueryRow(membershipSQL, userID, channelID)
	var temp int
	err1 := membershipQuery.Scan(&temp)
	messagesQuery, err2 := transaction.Query(getMessagesSQL, channelID)
	usersQuery, err3 := transaction.Query(getUsersSQL, channelID)
	getInfoQuery := transaction.QueryRow(getChannelInfoSQL, userID, channelID)
	var channelName string
	var encryptedKey string
	err4 := getInfoQuery.Scan(&channelName, &encryptedKey)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return
	}

	response := make(map[string]interface{})
	messages := make([]Message, 0, 1)
	users := make([]User, 0, 1)

	for messagesQuery.Next() {
		var messageId string
		var timestamp time.Time
		var username string
		var message string
		if err := messagesQuery.Scan(&messageId, &timestamp, &username, &message); err != nil {
			return
		}
		messages = append(messages, Message{messageId, timestamp, username, message})
	}
	for usersQuery.Next() {
		var userUuid string
		var username string
		if err := usersQuery.Scan(&userUuid, &username); err != nil {
			return
		}
		users = append(users, User{userUuid, username})
	}

	response["result"] = "success"
	response["name"] = channelName
	response["key"] = encryptedKey
	response["messages"] = messages
	response["users"] = users

	marshaledResponse, _ := json.Marshal(response)
	w.Write(marshaledResponse)
}

func main() {
	userConnections = make(map[string]*websocket.Conn)
	http.Handle("/", http.FileServer(http.Dir("./public/auth/")))
	http.Handle("/chat/", http.FileServer(http.Dir("./public/")))
	http.HandleFunc("/api/login", handleLoginRequest)
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/authenticate", handleAuthenticate)
	http.HandleFunc("/api/getKey", handleKeyRequest)
	http.HandleFunc("/api/getData", handleGetData)
	http.HandleFunc("/api/getChannel/{channelID}", handleGetChannelData)
	http.HandleFunc("/ws/{token}", handleWs)

	setup := false
	if _, err := os.Stat("database.db"); errors.Is(err, os.ErrNotExist) {
		setup = true
		createDatabase()
	}

	db, _ = sql.Open("sqlite3", "./database.db") // Open the created SQLite File
	defer db.Close()
	if setup {
		// encryptedPrivateKey, publicKey, and salt are all base64 encoded strings
		createUserTableSQL := `CREATE TABLE users (
		"uuid" TEXT NOT NULL PRIMARY KEY,		
		"email" TEXT NOT NULL UNIQUE,
		"username" TEXT NOT NULL UNIQUE,
		"encryptedPrivateKey" TEXT NOT NULL,
		"publicKey" TEXT NOT NULL,
		"salt" TEXT NOT NULL,
		"iv" TEXT NOT NULL
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

		// encryptedKey is base64 encoded string
		createMembershipTableSQL := `CREATE TABLE membership (
			"channelUuid" TEXT NOT NULL,		
			"userUuid" TEXT NOT NULL,
			"encryptedKey" TEXT NOT NULL,
			UNIQUE("channelUuid", "userUuid")
		);`

		_, err = db.Exec(createMembershipTableSQL)
		if err != nil {
			log.Fatal(err.Error())
		}

		// msg is base64 encoded string
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
