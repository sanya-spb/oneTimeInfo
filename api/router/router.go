package router

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"encoding/base64"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid"
	"github.com/sanya-spb/oneTimeInfo/api/handler"
	"golang.org/x/crypto/nacl/secretbox"
)

type Router struct {
	http.Handler
	hHandler  *handler.Handler
	secretKey [32]byte
}

type Token struct {
	Status    string    `json:"status"`
	FileID    uint      `json:"file"`
	ServiceID uint      `json:"service"`
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
}

const tokenStatusOk string = "ok"

type TInfo handler.TInfo

func (info *TInfo) Bind(r *http.Request) error {
	info.UUID = uuid.UUID{}
	info.CreatedAt = time.Now()

	return nil
}

func (token *Token) Bind(r *http.Request) error {
	if !(token.FileID > 0) {
		return errors.New("missing required field: file")
	}

	if !(token.ServiceID > 0) {
		return errors.New("missing required field: service")
	}

	if token.ValidFrom.IsZero() {
		token.ValidFrom = time.Now()
	}

	if token.ValidTo.IsZero() {
		token.ValidTo = time.Now().Add(time.Hour * 24 * 14)
	}

	token.Status = tokenStatusOk

	return nil
}

func (info *TInfo) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (token *Token) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func NewRouter(secretKey [32]byte, hHandler *handler.Handler) *Router {
	rRouter := &Router{
		hHandler:  hHandler,
		secretKey: secretKey,
	}

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.NoCache)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(60 * time.Second))

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "PUT", "POST", "DELETE", "HEAD", "OPTION"},
		AllowedHeaders:   []string{"User-Agent", "Content-Type", "Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Connection", "DNT", "Host", "Origin", "Pragma", "Referer"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	r.Route("/", func(r chi.Router) {
		r.Use(rRouter.BasicAuthentication)
		r.Get("/checkAuth", rRouter.CheckAuthBasic)
		r.Post("/token", rRouter.GetToken)
		r.Post("/upload", rRouter.CreateInfo)
		r.Get("/get/{uuid}", rRouter.ReadInfo)
		r.Get("/stat/{uuid}", rRouter.StatInfo)
	})

	r.Route("/r", func(r chi.Router) {
		r.Use(rRouter.BearerAuthentication)
		r.Get("/checkAuth", rRouter.CheckAuthBearer)
	})

	r.Get("/ui/*", rRouter.ui)

	rRouter.Handler = r
	return rRouter
}

// ValidateUser validates username and password returning an error if the user credentials are wrong
func (rRouter *Router) ValidateUser(username, password, scope string, r *http.Request) error {
	if rRouter.hHandler.CheckCredentials(username, password) {
		return nil
	}
	return errors.New("wrong user")
}

func renderJSON(w http.ResponseWriter, v interface{}, statusCode int) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = w.Write(buf.Bytes())
}

func (rRouter *Router) CheckAuthBasic(w http.ResponseWriter, r *http.Request) {
	type TResult struct {
		Status string `json:"status"`
		User   string `json:"login"`
		UID    uint   `json:"uid"`
		GID    uint   `json:"gid"`
	}

	user, _, _ := r.BasicAuth()
	vUser, _ := rRouter.hHandler.GetUser(user)

	result := TResult{
		Status: "ok",
		User:   user,
		UID:    vUser.UID,
		GID:    vUser.GID,
	}

	renderJSON(w, result, http.StatusOK)
}

func (rRouter *Router) CheckAuthBearer(w http.ResponseWriter, r *http.Request) {
	token, _ := TokenDecrypt(TokenFromHeader(r), rRouter.secretKey)

	renderJSON(w, token, http.StatusOK)
}

// Get user from authorization header.
func CredFromHeader(r *http.Request) string {
	cred := r.Header.Get("Authorization")
	if len(cred) > 6 && strings.ToUpper(cred[0:5]) == "basic" {
		return cred[6:]
	}
	return ""
}

// Get token from authorization header.
func TokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

func TokenEncrypt(token Token, secretKey [32]byte) (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("secretKey format error: %s", err.Error())
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("token serialization error: %s", err.Error())
	}

	encryptedToken := secretbox.Seal(nonce[:], []byte(tokenJSON), &nonce, &secretKey)

	return base64.StdEncoding.EncodeToString([]byte(encryptedToken)), nil
}

func TokenDecrypt(cryptedTokenBase64 string, secretKey [32]byte) (*Token, error) {
	cryptedToken, err := base64.StdEncoding.DecodeString(cryptedTokenBase64)
	if err != nil {
		return nil, fmt.Errorf("token format error: %s", err.Error())
	}

	log.Printf("len=%d", len(cryptedToken))
	if !(len(cryptedToken) > 24) {
		return nil, fmt.Errorf("token format error: %s", err.Error())
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], cryptedToken[:24])
	decrypted, ok := secretbox.Open(nil, cryptedToken[24:], &decryptNonce, &secretKey)
	if !ok {
		return nil, fmt.Errorf("token decryption error: %s", err.Error())
	}

	var token Token
	err = json.Unmarshal(decrypted, &token)
	if err != nil {
		return nil, fmt.Errorf("token deserialization error: %s", err.Error())
	}

	return &token, nil
}

func (rRouter *Router) BearerAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := TokenFromHeader(r)

		if bearer == "" {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		token, err := TokenDecrypt(TokenFromHeader(r), rRouter.secretKey)
		if err != nil {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		if token.Status != tokenStatusOk {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		if !token.ValidFrom.Before(time.Now()) {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}

		if !token.ValidTo.After(time.Now()) {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rRouter *Router) BasicAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		if user == "" || pass == "" {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		if !rRouter.hHandler.CheckCredentials(user, pass) {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rRouter *Router) ui(w http.ResponseWriter, r *http.Request) {
	root := "./data"
	fs := http.FileServer(http.Dir(root))

	url, err := r.URL.Parse(r.RequestURI)
	if err != nil {
		render.Render(w, r, Err500(err))
		return
	}

	if _, err := os.Stat(root + url.Path); os.IsNotExist(err) {
		http.StripPrefix(r.RequestURI, fs).ServeHTTP(w, r)
	} else {
		fs.ServeHTTP(w, r)
	}
}

func (rRouter *Router) GetToken(w http.ResponseWriter, r *http.Request) {
	type TResult struct {
		Token string `json:"token"`
	}

	var token Token
	if err := render.Bind(r, &token); err != nil {
		render.Render(w, r, Err400(err))
		return
	}

	tokenEncryptedBase64, err := TokenEncrypt(token, rRouter.secretKey)
	if err != nil {
		render.Render(w, r, Err400(err))
		return
	}

	renderJSON(w, TResult{Token: tokenEncryptedBase64}, http.StatusCreated)
}

func (rRouter *Router) CreateInfo(w http.ResponseWriter, r *http.Request) {
	type TResult struct {
		UUID uuid.UUID `json:"uuid"`
	}

	info := TInfo{}
	if err := render.Bind(r, &info); err != nil {
		render.Render(w, r, Err400(err))
		return
	}

	vUUID, err := rRouter.hHandler.Create(r.Context(), handler.TInfo(info))
	if err != nil {
		render.Render(w, r, Err500(err))
		return
	}

	renderJSON(w, TResult{UUID: vUUID}, http.StatusCreated)
}

func (rRouter *Router) ReadInfo(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	data, err := rRouter.hHandler.ReadInfo(r.Context(), uuid)
	if err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, r, Err404(err))
			return
		}
		render.Render(w, r, Err500(err))
		return
	}

	renderJSON(w, TInfo(data), http.StatusOK)
}

func (rRouter *Router) StatInfo(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")

	data, err := rRouter.hHandler.StatInfo(r.Context(), uuid)
	if err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, r, Err404(err))
			return
		}
		render.Render(w, r, Err500(err))
		return
	}

	renderJSON(w, TInfo(data), http.StatusOK)
}
