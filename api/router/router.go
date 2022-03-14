package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/oauth"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid"
	"github.com/sanya-spb/oneTimeInfo/api/handler"
)

type Router struct {
	http.Handler
	hHandler *handler.Handler
	secret   string
}

type TInfo handler.TInfo

func (info *TInfo) Bind(r *http.Request) error {
	// if info.Name == "" {
	// 	return errors.New("missing required field: Name")
	// }
	// if info.Type == "" {
	// 	return errors.New("missing required field: Type")
	// }
	// if info.Descr == "" {
	// 	return errors.New("missing required field: Descr")
	// }

	info.UUID = uuid.UUID{}
	info.CreatedAt = time.Now()

	return nil
}
func (info *TInfo) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func NewRouter(secret string, hHandler *handler.Handler) *Router {
	rRouter := &Router{
		hHandler: hHandler,
		// secret:   secret,
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

	s := oauth.NewBearerServer(
		secret,
		time.Second*120,
		&UserVerifier{},
		nil)

	r.Post("/oauth/token", s.UserCredentials)
	// r.Post("/oauth/auth", s.ClientCredentials)

	r.Route("/", func(r chi.Router) {
		// use the Bearer Authentication middleware
		r.Use(oauth.Authorize(secret, nil))
		r.Get("/checkAuth", CheckAuth)
		r.Post("/upload", rRouter.CreateInfo)
		r.Get("/get/{uuid}", rRouter.ReadInfo)
		r.Get("/stat/{uuid}", rRouter.StatInfo)
	})

	r.Get("/ui/*", rRouter.ui)

	rRouter.Handler = r
	return rRouter
}

// UserVerifier provides user credentials verifier.
type UserVerifier struct {
}

// ValidateUser validates username and password returning an error if the user credentials are wrong
func (*UserVerifier) ValidateUser(username, password, scope string, r *http.Request) error {
	if username == "test" && password == "12345678" {
		// ctx := context.WithValue(r.Context(), "user_id", 1001)
		// r.WithContext(ctx)
		// next.ServeHTTP(w, r.WithContext(ctx))

		return nil
	}

	return errors.New("wrong user")
}

// ValidateClient validates clientID and secret returning an error if the client credentials are wrong
func (*UserVerifier) ValidateClient(clientID, clientSecret, scope string, r *http.Request) error {
	// if clientID == "abcdef" && clientSecret == "12345" {
	// 	return nil
	// }

	return errors.New("wrong client")
}

// ValidateCode validates token ID
func (*UserVerifier) ValidateCode(clientID, clientSecret, code, redirectURI string, r *http.Request) (string, error) {
	return "", nil
}

// AddClaims provides additional claims to the token
func (*UserVerifier) AddClaims(tokenType oauth.TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error) {
	claims := make(map[string]string)
	claims["user_id"] = "1001"
	// claims["customer_data"] = `{"order_date":"2016-12-14","order_id":"9999"}`
	return claims, nil
}

// AddProperties provides additional information to the token response
func (*UserVerifier) AddProperties(tokenType oauth.TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error) {
	props := make(map[string]string)
	props["auth_server_name"] = "otin-backend"
	return props, nil
}

// ValidateTokenID validates token ID
func (*UserVerifier) ValidateTokenID(tokenType oauth.TokenType, credential, tokenID, refreshTokenID string) error {
	return nil
}

// StoreTokenID saves the token id generated for the user
func (*UserVerifier) StoreTokenID(tokenType oauth.TokenType, credential, tokenID, refreshTokenID string) error {
	return nil
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

func CheckAuth(w http.ResponseWriter, req *http.Request) {
	type TResult struct {
		Status string `json:"status"`
		UserID string `json:"user_id"`
	}

	claim := req.Context().Value(oauth.ClaimsContext).(map[string]string)

	renderJSON(w, TResult{Status: "verified", UserID: claim["user_id"]}, http.StatusOK)
}

func (rRouter *Router) ui(w http.ResponseWriter, req *http.Request) {
	root := "./data"
	fs := http.FileServer(http.Dir(root))

	url, err := req.URL.Parse(req.RequestURI)
	if err != nil {
		render.Render(w, req, Err500(err))
		return
	}

	if _, err := os.Stat(root + url.Path); os.IsNotExist(err) {
		http.StripPrefix(req.RequestURI, fs).ServeHTTP(w, req)
	} else {
		fs.ServeHTTP(w, req)
	}
}

func (rRouter *Router) CreateInfo(w http.ResponseWriter, req *http.Request) {
	type TResult struct {
		UUID uuid.UUID `json:"uuid"`
	}

	info := TInfo{}
	if err := render.Bind(req, &info); err != nil {
		render.Render(w, req, Err400(err))
		return
	}

	vUUID, err := rRouter.hHandler.Create(req.Context(), handler.TInfo(info))
	if err != nil {
		render.Render(w, req, Err500(err))
		return
	}

	renderJSON(w, TResult{UUID: vUUID}, http.StatusCreated)
}

func (rRouter *Router) ReadInfo(w http.ResponseWriter, req *http.Request) {
	uuid := chi.URLParam(req, "uuid")

	data, err := rRouter.hHandler.ReadInfo(req.Context(), uuid)
	if err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, req, Err404(err))
			return
		}
		render.Render(w, req, Err500(err))
		return
	}

	renderJSON(w, TInfo(data), http.StatusOK)
}

func (rRouter *Router) StatInfo(w http.ResponseWriter, req *http.Request) {
	uuid := chi.URLParam(req, "uuid")

	data, err := rRouter.hHandler.StatInfo(req.Context(), uuid)
	if err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, req, Err404(err))
			return
		}
		render.Render(w, req, Err500(err))
		return
	}

	renderJSON(w, TInfo(data), http.StatusOK)
}
