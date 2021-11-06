package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type User struct {
	Email       string
	Credentials []webauthn.Credential
}

// User ID according to the Relying Party
func (u User) WebAuthnID() []byte {
	return []byte(u.Email)
}

// User Name according to the Relying Party
func (u User) WebAuthnName() string {
	return u.Email
}

// Display Name of the user
func (u User) WebAuthnDisplayName() string {
	return u.Email + " displayName"
}

// User's icon url
func (u User) WebAuthnIcon() string {
	return ""
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

var users = make(map[string]webauthn.User)

func main() {
	wAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "WebAuthnデモ",
		RPID:          "localhost",
		RPOrigin:      "http://localhost:8080",
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
			sess, _ := session.Get("sessionid", c)
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

	e.GET("/register/:email", func(c echo.Context) (err error) {
		sess := c.Get("session").(*sessions.Session)

		email, err := url.PathUnescape(c.Param("email"))
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		user, ok := users[email]
		if !ok {
			user = User{
				Email: email,
			}
		}

		options, sessionData, err := wAuthn.BeginRegistration(user)
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

	e.POST("/register", func(c echo.Context) (err error) {
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

		user := User{
			Email: string(sessionData.UserID),
		}

		credential, err := wAuthn.FinishRegistration(user, sessionData, c.Request())
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		user.Credentials = append(user.Credentials, *credential)

		users[user.Email] = user

		delete(sess.Values, "webauthn-register")

		return c.JSON(http.StatusOK, "Registration Success.")
	})

	e.GET("/login/:email", func(c echo.Context) (err error) {
		sess := c.Get("session").(*sessions.Session)

		email, err := url.PathUnescape(c.Param("email"))
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		user, ok := users[email]
		if !ok {
			c.JSON(http.StatusBadRequest, "user not found.")
			return
		}

		options, sessionData, err := wAuthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationPreferred))
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		sessionDataJSON, err := json.Marshal(sessionData)
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}
		sess.Values["webauthn-login"] = sessionDataJSON

		return c.JSON(http.StatusOK, options)
	})

	e.POST("/login", func(c echo.Context) (err error) {
		sess := c.Get("session").(*sessions.Session)

		sessionDataJSON, ok := sess.Values["webauthn-login"]
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

		user, ok := users[string(sessionData.UserID)]
		if !ok {
			c.JSON(http.StatusBadRequest, "user not found.")
			return
		}

		_, err = wAuthn.FinishLogin(user, sessionData, c.Request())
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		delete(sess.Values, "webauthn-login")

		return c.JSON(http.StatusOK, "Registration Success.")
	})

	e.Start(":8080")
}
