package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"encoding/base64"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/sanya-spb/oneTimeInfo/api/handler"
)

type Router struct {
	http.Handler
	hHandler *handler.Handler
}

const (
	tokenStatusOk string = "ok"
	adminGID      uint   = 1
	userGID       uint   = 100
)

type TInfo handler.TInfo
type Token handler.Token

func (info *TInfo) Bind(r *http.Request) error {
	if info.Name == "" {
		return errors.New("missing required field: name")
	}

	if info.Descr == "" {
		return errors.New("missing required field: descr")
	}

	if info.DataBase64 == "" {
		return errors.New("missing required field: data")
	}

	var (
		data []byte
		err  error
	)

	if data, err = base64.StdEncoding.DecodeString(info.DataBase64); err != nil {
		return fmt.Errorf("data format error: %s", err)
	}

	if info.IsFile {
		info.Size = len(data)
	} else {
		info.Size = utf8.RuneCountInString(string(data))
	}

	if info.CreatedAt.IsZero() {
		info.CreatedAt = time.Now().Round(time.Second)
	}

	if info.DeleteAt.IsZero() {
		info.DeleteAt = time.Now().Add(time.Hour * 24 * 14).Round(time.Second)
	}

	return nil
}

func (info TInfo) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func NewRouter(hHandler *handler.Handler) *Router {
	rRouter := &Router{
		hHandler: hHandler,
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
		// AllowedOrigins:   []string{"*"},
		AllowedOrigins: []string{"https://*", "http://*"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{
			"User-Agent", "Content-Type", "Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Connection",
			"DNT", "Host", "Origin", "Pragma", "Referer",
		},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/img/favicon.ico", http.StatusFound)
	})

	r.Route("/token", func(r chi.Router) {
		r.Use(rRouter.BasicAuthentication)
		// r.Get("/checkAuth", rRouter.CheckAuthBasic)
		r.Get("/", rRouter.Token)
	})

	r.Route("/", func(r chi.Router) {
		r.Use(rRouter.BearerAuthentication)

		// admin
		r.Post("/upload", rRouter.CreateInfo)
		r.Get("/list", rRouter.ListInfo)

		// for development period only (unsecured!)
		// r.Get("/checkAuth", rRouter.CheckAuthBearer)

		// users
		r.Get("/g", rRouter.ReadInfo)
		r.Get("/s", rRouter.StatInfo)
	})

	r.Get("/ui/*", rRouter.ui)
	rRouter.Handler = r

	return rRouter
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
		Status: tokenStatusOk,
		User:   user,
		UID:    vUser.UID,
		GID:    vUser.GID,
	}

	renderJSON(w, result, http.StatusOK)
}

func (rRouter *Router) CheckAuthBearer(w http.ResponseWriter, r *http.Request) {
	token, _ := rRouter.hHandler.DecryptToken(TokenFromHeader(r))

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

func (rRouter *Router) BearerAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := TokenFromHeader(r)

		if bearer == "" {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		token, err := rRouter.hHandler.DecryptToken(TokenFromHeader(r))
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
		_ = render.Render(w, r, Err500(err))
		return
	}

	if _, err := os.Stat(root + url.Path); os.IsNotExist(err) {
		http.StripPrefix(r.RequestURI, fs).ServeHTTP(w, r)
	} else {
		fs.ServeHTTP(w, r)
	}
}

func (rRouter *Router) Token(w http.ResponseWriter, r *http.Request) {
	type TResult struct {
		Token string `json:"token"`
	}

	user, _, _ := r.BasicAuth()
	vUser, _ := rRouter.hHandler.GetUser(user)

	if vUser.GID != adminGID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	token := Token{
		Status:    tokenStatusOk,
		UID:       vUser.UID,
		GID:       vUser.GID,
		ValidFrom: time.Now(),
		ValidTo:   time.Now().Add(time.Minute * 30),
	}

	tokenEncryptedBase64, err := rRouter.hHandler.EncryptToken(handler.Token(token))
	if err != nil {
		_ = render.Render(w, r, Err500(err))
		return
	}

	renderJSON(w, TResult{Token: tokenEncryptedBase64}, http.StatusOK)
}

func (rRouter *Router) CreateInfo(w http.ResponseWriter, r *http.Request) {
	type TResult struct {
		Status    string `json:"status"`
		Token     string `json:"token"`
		TokenData Token
	}

	token, _ := rRouter.hHandler.DecryptToken(TokenFromHeader(r))

	if token.GID != adminGID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	info := TInfo{}
	if err := render.Bind(r, &info); err != nil {
		_ = render.Render(w, r, Err400(err))
		return
	}

	id, err := rRouter.hHandler.Create(r.Context(), handler.TInfo(info))
	if err != nil {
		_ = render.Render(w, r, Err500(err))
		return
	}

	vInfo, err := rRouter.hHandler.StatInfo(r.Context(), id)
	if err != nil {
		_ = render.Render(w, r, Err500(err))
		return
	}

	userToken := Token{
		Status:    tokenStatusOk,
		FileID:    id,
		GID:       100,
		ValidFrom: vInfo.CreatedAt,
		ValidTo:   vInfo.DeleteAt,
	}

	tokenEncryptedBase64, err := rRouter.hHandler.EncryptToken(handler.Token(userToken))
	if err != nil {
		_ = render.Render(w, r, Err500(err))
		return
	}

	result := TResult{
		Status:    tokenStatusOk,
		Token:     tokenEncryptedBase64,
		TokenData: userToken,
	}
	renderJSON(w, result, http.StatusCreated)
}

func (rRouter *Router) ListInfo(w http.ResponseWriter, r *http.Request) {
	token, _ := rRouter.hHandler.DecryptToken(TokenFromHeader(r))

	if token.GID != adminGID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	chin, err := rRouter.hHandler.ListInfo(r.Context())
	if err != nil {
		_ = render.Render(w, r, Err500(err))
		return
	}

	first := true

	for {
		select {
		case <-r.Context().Done():
			_ = render.Render(w, r, Err500(err))
			return
		case data, ok := <-chin:
			if !ok {
				if !first {
					fmt.Fprintln(w, "]}")
				}

				return
			}

			if first {
				first = false

				fmt.Fprintln(w, "{ \"data\": [")
			} else {
				fmt.Fprintln(w, ",")
			}

			_ = render.Render(w, r, TInfo(data))
		}
	}
}

func (rRouter *Router) StatInfo(w http.ResponseWriter, r *http.Request) {
	token, _ := rRouter.hHandler.DecryptToken(TokenFromHeader(r))

	if token.GID != userGID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	data, err := rRouter.hHandler.StatInfo(r.Context(), token.FileID)
	if err != nil {
		if errors.Is(err, handler.ErrInfoNotFound) {
			_ = render.Render(w, r, Err404(err))
			return
		}

		_ = render.Render(w, r, Err500(err))

		return
	}

	renderJSON(w, TInfo(data), http.StatusOK)
}

func (rRouter *Router) ReadInfo(w http.ResponseWriter, r *http.Request) {
	token, _ := rRouter.hHandler.DecryptToken(TokenFromHeader(r))

	if token.GID != userGID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	data, err := rRouter.hHandler.ReadInfo(r.Context(), token.FileID)
	if err != nil {
		if errors.Is(err, handler.ErrInfoNotFound) {
			_ = render.Render(w, r, Err404(err))
			return
		}

		_ = render.Render(w, r, Err500(err))

		return
	}

	renderJSON(w, TInfo(data), http.StatusOK)
}
