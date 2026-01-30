package main

import(
	"encoding/json" // json to struct and vice versa
	"time"
	"net/http"
	"github.com/golang-jwt/jwt/v5"

	"fmt" //for writiing text to response writer w
	"strings" // when the client sends the token, they send it as Bearer eyJhbG.... this library cuts off the "Bearer " so we have the raw token

	"crypto/rand" //generate random numbers
	"encoding/base64" // turn them into strings
)

var seckey = []byte("my_secret_key")  // coz jwt expects bytes

// i am creating a dummy db with key(RT string) and value (username)
var RefreshToken = map[string]string{} // to store refresh tokens against usernames

type Credentials struct{
	Username string `json:"username"` // captialized to be exported(Public), so that json package can access it
	Password string `json:"password"` // when json sees 'username' in incoming text, it maps it to Username field
}

// claiims struct defines the payload
type Claims struct {
    Username string `json:"username"`
    jwt.RegisteredClaims
}

// cntainer for the refresh request
type RefreshRequest struct {
    RefreshToken string `json:"refresh_token"`
}

func Login(w http.ResponseWriter, r *http.Request){
	// anything you write to w gets sent back to the user as response
	// * is a pointer to request struct... anything you read from r is what the user sent to you in the request

	// 1. create a container to hold incoming credentials
	var creds Credentials 

	// 2 decode
	json.NewDecoder(r.Body).Decode(&creds) // decode request body into cred struct
	// r.Body is raw stream of bytes form user..
    // Decode(&creds) reads that stream and fills our variable.


	// 3. set the exp time
	expirationtime := time.Now().Add(1* time.Minute) // reducing from 10 to 1 min for testing

	// 4 create the claims (payload)
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{		// struct provided by jwt package contains fields like ExpiresAt, IssuedAt etc
			ExpiresAt: jwt.NewNumericDate(expirationtime), // this function converts Go-Time to the format JWT expects
		},
	}

	// 5 creating the token object

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // create token with claims and signing method

	// 6 sign token with secret key
	tokenString, _ := token.SignedString(seckey) // takes the haeder and payload, signs it with secret key and returns the complete token

	// 7 refresh token generation

	randomBytes := make([]byte, 32) // list of 32 empty bytes
	rand.Read(randomBytes) // fill it with random bytes

	refreshTokenString := base64.URLEncoding.EncodeToString(randomBytes) // turn random bytes into string

	// 8 store the refresh token against the username in our dummy db
	RefreshToken[refreshTokenString] = creds.Username

	// 9. set the content type

	w.Header().Set("Content-Type", "application/json")

	// 10. send the token back as response
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": tokenString,
		"refresh_token": refreshTokenString,
	})
}

func Home(w http.ResponseWriter, r *http.Request){
	fmt.Fprintf(w, "access token valid!")
}

func IsAuthorized(next http.HandlerFunc) http.HandlerFunc{  // it is s higher order function that takes another function as input.. input 'next' the function we want to protect
	return func(w http.ResponseWriter, r *http.Request){
		
		authHeader := r.Header.Get("Authorization") // get the authorization header from the request
		if authHeader == ""{
			w.WriteHeader(http.StatusUnauthorized) // 401
			fmt.Fprintf(w, "no token found")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ") // remove the "Bearer" part from the header value to get the actual token
		claims := &Claims{} // create an empty claims struct to hold the parsed claims

		// parse the token
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return seckey, nil // return the secret key for validation
		})

		// did it pass?

		if err != nil || !token.Valid{
			w.WriteHeader(http.StatusUnauthorized) // 401
			fmt.Fprintf(w, "invalid token")
			return
		}
		// if valid, call the next handler
		next(w, r)

	}
}

func Refresh(w http.ResponseWriter, r *http.Request) {
    
	// 1 decode the json to get the token string
    var req RefreshRequest
    err := json.NewDecoder(r.Body).Decode(&req)
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    // 2.check the db
    // Syntax: value, exists := map[key]

    username, ok := RefreshToken[req.RefreshToken]

    if !ok {        // if the token is in the map, ok is true, and 'username' is "admin".. and if not, ok is false.
        w.WriteHeader(http.StatusUnauthorized)
        fmt.Fprint(w, "Invalid Refresh Token")
        return
    }

    // 3. create a access token

    // exact same logic as login as odne earlier...
    expirationTime := time.Now().Add(5 * time.Minute)

    claims := &Claims{
        Username: username, // use the username we found in the map
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, _ := token.SignedString(seckey)

    // 4. send the new jwt back
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "access_token": tokenString,
    })
}

func main(){
	http.HandleFunc("/login", Login) 
	http.HandleFunc("/home", IsAuthorized(Home)) //  /home endpoint hit; call IsAuthorized(Home) func
	http.HandleFunc("/refresh", Refresh) // refresh route
	fmt.Println("server started at :8000")
	http.ListenAndServe(":8000", nil)
}
