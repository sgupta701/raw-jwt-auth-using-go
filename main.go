package main

import(
    "encoding/json"
    "time"
    "net/http"
    "github.com/golang-jwt/jwt/v5"
)

var seckey = []byte("my_secret_key")  //done coz jwt expect bytes

type Credentials struct{
    Username string `json:"username"` // captialized to be exported(Public), so that json package can access it
    Password string `json:"password"` // when json sees 'username' in incoming text, it maps it to Username field
}

// claiims struct defines the payload
type Claims struct {
    Username string `json:"username"`
    jwt.RegisteredClaims
}

func Login(w http.ResponseWriter, r *http.Request){
    // anything we write to w gets sent back to the user as response
    // * is a pointer to request struct... anything we read from r is what the user sent to us in the request

    // 1. create a container to hold incoming credentials
    var creds Credentials 

    // 2 decode
    json.NewDecoder(r.Body).Decode(&creds) // decode request body into cred struct
    // r.Body is raw stream of bytes form user..
    // Decode(&creds) reads that stream and fills our variable.

    // 3. set the exp time
    expirationtime := time.Now().Add(10* time.Minute)

    // 4 create the claims (payload)
    claims := &Claims{
        Username: creds.Username,
        RegisteredClaims: jwt.RegisteredClaims{     // struct provided by jwt package contains fields like ExpiresAt, IssuedAt etc
            ExpiresAt: jwt.NewNumericDate(expirationtime), // this function converts Go-Time to the format JWT expects
	},
    }

    // 5 creating the token object

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // create token with claims and signing method

    // 6 sign token with secret key
    tokenString, _ := token.SignedString(seckey) // takes the haeder and payload, signs it with secret key and returns the complete token

    // 7. set the content type

    w.Header().Set("Content-Type", "application/json")

    // 9. send the token back as response
    json.NewEncoder(w).Encode(map[string]string{
        "token": tokenString,
    })
}

func main(){
    http.HandleFunc("/login", Login) // when user hits /login endpoint, call Login function
    http.ListenAndServe(":8000", nil)
}
