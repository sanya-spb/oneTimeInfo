package main

import (
	"context"
	"os"
	"os/signal"
	"sync"

	"github.com/sanya-spb/oneTimeInfo/api/handler"
	"github.com/sanya-spb/oneTimeInfo/api/router"
	"github.com/sanya-spb/oneTimeInfo/api/server"
	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
	"github.com/sanya-spb/oneTimeInfo/app/starter"
	"github.com/sanya-spb/oneTimeInfo/db/memory/info/store"
	"github.com/sirupsen/logrus"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	log := logrus.New()
	store := store.NewInfo()
	app, err := starter.NewApp(ctx, log, store)
	if err != nil {
		log.Fatal(err.Error())
	}

	app.Welcome()

	vInfo := info.NewInfo(store)
	appHandler := handler.NewHandler(vInfo)
	appRouter := router.NewRouter(app.Config.SecretKey, appHandler)
	appServer := server.NewServer(app.Config.Listen, appRouter)

	wg := &sync.WaitGroup{}
	wg.Add(1)

	log.Infof("listen at: %s", appServer.Addr())
	go app.Serve(ctx, wg, appServer)

	<-ctx.Done()
	cancel()
	wg.Wait()
}
