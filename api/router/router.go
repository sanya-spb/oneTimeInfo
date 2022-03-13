package router

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/sanya-spb/oneTimeInfo/api/handler"
)

type Router struct {
	http.Handler
	hHandler *handler.Handler
}

type TInfo handler.TInfo

func (info *TInfo) Bind(r *http.Request) error {
	if info.Name == "" {
		return errors.New("missing required field: Name")
	}
	if info.URL == "" {
		return errors.New("missing required field: URL")
	}
	if info.Descr == "" {
		return errors.New("missing required field: Descr")
	}

	info.ID = ""
	info.CreatedAt = time.Now()

	return nil
}
func (TInfo) Render(w http.ResponseWriter, r *http.Request) error {
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

	r.Group(func(rAdm chi.Router) {
		rAdm.Use(middleware.BasicAuth("Auth needed", map[string]string{"admin": "TqmodV4MqYcsgqdX"}))

		rAdm.Get("/stat", rRouter.Stat)
		rAdm.Put("/{id}", rRouter.Update)
		rAdm.Post("/r/{id}", rRouter.UpdateRet)
		rAdm.Delete("/d/{id}", rRouter.Delete)
		rAdm.Delete("/d/r/{id}", rRouter.DeleteRet)
		rAdm.Get("/status/{code}", rRouter.StatusCode)

		rAdm.Get("/ui/*", rRouter.ui)
	})
	r.Put("/", rRouter.Create)
	r.Get("/i/{id}", rRouter.Read)
	r.Get("/status", rRouter.Status)
	r.Get("/{id}", rRouter.Go)

	rRouter.Handler = r
	return rRouter
}

func (rRouter *Router) Create(w http.ResponseWriter, req *http.Request) {
	info := TInfo{}
	if err := render.Bind(req, &info); err != nil {
		render.Render(w, req, Err400(err))
		return
	}
	hLink, err := rRouter.hHandler.Create(req.Context(), handler.TInfo(info))
	if err != nil {
		render.Render(w, req, Err500(err))
		return
	}
	render.Status(req, http.StatusCreated)
	render.Render(w, req, TInfo(hLink))
}

func (rRouter *Router) Read(w http.ResponseWriter, req *http.Request) {
	id := chi.URLParam(req, "id")

	hLink, err := rRouter.hHandler.Read(req.Context(), id)
	if err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, req, Err404(err))
			return
		}
		render.Render(w, req, Err500(err))
		return
	}
	render.Render(w, req, TInfo(hLink))
}

func (rRouter *Router) Update(w http.ResponseWriter, req *http.Request) {
	id := chi.URLParam(req, "id")

	info := TInfo{}
	if err := render.Bind(req, &info); err != nil {
		render.Render(w, req, Err400(err))
		return
	}
	if err := rRouter.hHandler.Update(req.Context(), id, handler.TInfo(info)); err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, req, Err404(err))
			return
		}
		render.Render(w, req, Err500(err))
		return
	}
	render.Status(req, http.StatusNoContent)
}

func (rRouter *Router) UpdateRet(w http.ResponseWriter, req *http.Request) {
	id := chi.URLParam(req, "id")

	info := TInfo{}
	if err := render.Bind(req, &info); err != nil {
		render.Render(w, req, Err400(err))
		return
	}
	hLink, err := rRouter.hHandler.UpdateRet(req.Context(), id, handler.TInfo(info))
	if err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, req, Err404(err))
			return
		}
		render.Render(w, req, Err500(err))
		return
	}
	render.Render(w, req, TInfo(hLink))
}

func (rRouter *Router) Delete(w http.ResponseWriter, req *http.Request) {
	id := chi.URLParam(req, "id")

	if err := rRouter.hHandler.Delete(req.Context(), id); err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, req, Err404(err))
			return
		}
		render.Render(w, req, Err500(err))
		return
	}
	render.Status(req, http.StatusNoContent)
}

func (rRouter *Router) DeleteRet(w http.ResponseWriter, req *http.Request) {
	id := chi.URLParam(req, "id")

	hLink, err := rRouter.hHandler.DeleteRet(req.Context(), id)
	if err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, req, Err404(err))
			return
		}
		render.Render(w, req, Err500(err))
		return
	}
	render.Render(w, req, TInfo(hLink))
}

func (rRouter *Router) Status(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(w, "ok")
}

func (rRouter *Router) StatusCode(w http.ResponseWriter, req *http.Request) {
	code := chi.URLParam(req, "code")
	fmt.Fprintln(w, code)
}

func (rRouter *Router) Go(w http.ResponseWriter, req *http.Request) {
	id := chi.URLParam(req, "id")

	url, err := rRouter.hHandler.Go(req.Context(), id)
	if err != nil {
		if errors.As(err, &handler.ErrInfoNotFound) {
			render.Render(w, req, Err404(err))
			return
		}
		render.Render(w, req, Err500(err))
		return
	}

	http.Redirect(w, req, url, http.StatusTemporaryRedirect)
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

func (rRouter *Router) Stat(w http.ResponseWriter, req *http.Request) {
	chin, err := rRouter.hHandler.Stat(req.Context())
	if err != nil {
		render.Render(w, req, Err500(err))
		return
	}

	first := true
	for {
		select {
		case <-req.Context().Done():
			render.Render(w, req, Err500(err))
			return
		case data, ok := <-chin:
			if !ok {
				if !first {
					first = false
					fmt.Fprintln(w, "]}")
				}
				return
			}
			if first {
				first = false
				fmt.Fprintln(w, "{ \"Links\": [")
			} else {
				fmt.Fprintln(w, ",")
			}
			render.Render(w, req, TInfo(data))
		}
	}
}
