package server

import (
	"context"
	"net/http"
	"time"

	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
)

type Server struct {
	httpServer http.Server
	info       *info.Info
}

func NewServer(addr string, h http.Handler) *Server {
	s := &Server{}

	s.httpServer = http.Server{
		Addr:              addr,
		Handler:           h,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
	}

	return s
}

func (srv *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.httpServer.Shutdown(ctx)

	cancel()
}

func (srv *Server) Start(info *info.Info) {
	srv.info = info

	go func() {
		_ = srv.httpServer.ListenAndServe()
	}()
}

func (srv *Server) Addr() string {
	return srv.httpServer.Addr
}
