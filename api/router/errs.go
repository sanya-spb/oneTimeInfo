package router

import (
	"net/http"

	"github.com/go-chi/render"
)

type ErrResponse struct {
	Err            error `json:"-"` // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText string `json:"status"`          // user-level status message
	AppCode    int64  `json:"code,omitempty"`  // application-specific error code
	ErrorText  string `json:"error,omitempty"` // application-level error message, for debugging
}

func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

// 400 Bad Request
func Err400(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 400,
		StatusText:     "Bad Request",
		ErrorText:      err.Error(),
	}
}

// 403 Forbidden
func Err403(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 403,
		StatusText:     "Forbidden",
		ErrorText:      err.Error(),
	}
}

// 404 Not Found
func Err404(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 404,
		StatusText:     "Not Found",
		ErrorText:      err.Error(),
	}
}

// 405 Method Not Allowed
func Err405(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 405,
		StatusText:     "Method Not Allowed",
		ErrorText:      err.Error(),
	}
}

// 409 Conflict
func Err409(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 409,
		StatusText:     "Conflict",
		ErrorText:      err.Error(),
	}
}

// 500 Internal Server Error
func Err500(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 500,
		StatusText:     "Internal Server Error",
		ErrorText:      err.Error(),
	}
}

// 501 Not Implemented
func Err501(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 501,
		StatusText:     "Not Implemented",
		ErrorText:      err.Error(),
	}
}

var ErrNotFound = &ErrResponse{HTTPStatusCode: 404, StatusText: "Resource not found."}
