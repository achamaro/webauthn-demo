package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type User struct {
	ID          string
	Name        string
	Icon        string
	Email       string
	Credentials []webauthn.Credential
}

// User ID according to the Relying Party
// User Handle に使用されるため、メールアドレスやユーザー名を含めてはいけない
// User Handle Contents
// MUST NOT include personally identifying information, e.g., e-mail addresses or usernames, in the user handle.
// It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user’s account.
func (u User) WebAuthnID() []byte {
	bytes, _ := hex.DecodeString(u.ID)
	return bytes
}

// User Name according to the Relying Party
func (u User) WebAuthnName() string {
	return u.Email
}

// Display Name of the user
func (u User) WebAuthnDisplayName() string {
	return u.Name
}

// User's icon url
func (u User) WebAuthnIcon() string {
	return u.Icon
}

// Credentials owned by the user
func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's credentials
func (u User) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.Credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

type UserRepository struct {
	users []*User
}

func (u *UserRepository) Add(user *User) {
	u.users = append(u.users, user)
}

func (u UserRepository) FindByID(id []byte) (*User, bool) {
	for _, user := range u.users {
		if bytes.Equal(user.WebAuthnID(), id) {
			return user, true
		}
	}
	return nil, false
}

func (u UserRepository) FindByEmail(email string) (*User, bool) {
	for _, user := range u.users {
		if user.Email == email {
			return user, true
		}
	}
	return nil, false
}

var userRepo = UserRepository{}

func main() {
	wAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "WebAuthnデモ",
		RPID:          "localhost",
		RPOrigin:      "http://localhost:8080",
		RPIcon:        "http://localhost:8080/images/touch-id.png",
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
			// ID/パスワードレス認証をするためにレジデントキーを登録する
			RequireResidentKey: protocol.ResidentKeyRequired(),
			// ユーザー認証を必須にする
			UserVerification: protocol.VerificationRequired,
		},
		// 認証器の検証は行わない
		// attestation: none
		// none以外はデバイス情報を取得してよいかの確認が入る
		AttestationPreference: protocol.ConveyancePreference(protocol.PreferNoAttestation),
	})

	if err != nil {
		panic(err)
	}

	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Static("public"))
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			sess, _ := session.Get("session", c)
			sess.Options = &sessions.Options{
				Path:     "/",
				MaxAge:   86400 * 7,
				HttpOnly: true,
			}
			c.Set("session", sess)

			c.Response().Before(func() {
				err := sess.Save(c.Request(), c.Response())
				if err != nil {
					fmt.Println(err)
				}
			})

			err := next(c)

			c.Set("session", nil)

			return err
		}
	})

	e.POST("/auth/webauthn/register/request", func(c echo.Context) (err error) {
		sess := c.Get("session").(*sessions.Session)

		email := c.FormValue("email")

		user, ok := userRepo.FindByEmail(email)
		if !ok {
			// 新規ユーザー
			idBytes := make([]byte, 64)
			rand.Read(idBytes)

			user = &User{
				ID:    hex.EncodeToString(idBytes),
				Email: email,
				Name:  c.FormValue("name"),
				Icon:  c.FormValue("icon"),
			}

			userRepo.Add(user)
		}

		options, sessionData, err := wAuthn.BeginRegistration(
			user,
			// BeginRegistrationの内部でConfigの値が使用されないので設定
			webauthn.WithAuthenticatorSelection(wAuthn.Config.AuthenticatorSelection),
		)
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}
		sessionDataJSON, err := json.Marshal(sessionData)
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}
		sess.Values["webauthn-register"] = sessionDataJSON

		return c.JSON(http.StatusOK, options)
	})

	e.POST("/auth/webauthn/register/response", func(c echo.Context) (err error) {
		sess := c.Get("session").(*sessions.Session)

		sessionDataJSON, ok := sess.Values["webauthn-register"]
		if !ok {
			c.JSON(http.StatusBadRequest, "session data not exists.")
			return
		}

		sessionData := webauthn.SessionData{}
		err = json.Unmarshal(sessionDataJSON.([]byte), &sessionData)
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		user, ok := userRepo.FindByID(sessionData.UserID)
		if !ok {
			c.JSON(http.StatusBadRequest, "user not found.")
			return
		}

		credential, err := wAuthn.FinishRegistration(user, sessionData, c.Request())
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		user.Credentials = append(user.Credentials, *credential)

		delete(sess.Values, "webauthn-register")

		return c.JSON(http.StatusOK, "Registration Success.")
	})

	e.GET("/auth/webauthn/signin/request", func(c echo.Context) (err error) {
		sess := c.Get("session").(*sessions.Session)

		options, sessionData, err := BeginLogin(wAuthn)
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		sessionDataJSON, err := json.Marshal(sessionData)
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}
		sess.Values["webauthn-signin"] = sessionDataJSON

		return c.JSON(http.StatusOK, options)
	})

	e.POST("/auth/webauthn/signin/response", func(c echo.Context) (err error) {
		sess := c.Get("session").(*sessions.Session)

		sessionDataJSON, ok := sess.Values["webauthn-signin"]
		if !ok {
			c.JSON(http.StatusBadRequest, "session data not exists.")
			return
		}

		sessionData := webauthn.SessionData{}
		err = json.Unmarshal(sessionDataJSON.([]byte), &sessionData)
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		parsedResponse, err := protocol.ParseCredentialRequestResponse(c.Request())
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		user, ok := userRepo.FindByID(parsedResponse.Response.UserHandle)
		if !ok {
			c.JSON(http.StatusBadRequest, "user not found.")
			return
		}
		sessionData.UserID = parsedResponse.Response.UserHandle

		_, err = wAuthn.ValidateLogin(user, sessionData, parsedResponse)
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		delete(sess.Values, "webauthn-signin")

		return c.JSON(http.StatusOK, "Registration Success.")
	})

	e.Start(":8080")
}

func BeginLogin(w *webauthn.WebAuthn) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, nil, err
	}

	requestOptions := protocol.PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		Timeout:          w.Config.Timeout,
		RelyingPartyID:   w.Config.RPID,
		UserVerification: w.Config.AuthenticatorSelection.UserVerification,
	}

	newSessionData := webauthn.SessionData{
		Challenge:            base64.RawURLEncoding.EncodeToString(challenge),
		AllowedCredentialIDs: requestOptions.GetAllowedCredentialIDs(),
		UserVerification:     requestOptions.UserVerification,
	}

	response := protocol.CredentialAssertion{
		Response: requestOptions,
	}

	return &response, &newSessionData, nil

}
