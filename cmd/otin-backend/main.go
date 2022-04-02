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
	"github.com/sanya-spb/oneTimeInfo/db/redis/info/store"
	"github.com/sirupsen/logrus"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	log := logrus.New()
	app, err := starter.NewApp(ctx, log)
	if err != nil {
		log.Fatal(err.Error())
	}

	app.Welcome()

	vStore := store.NewInfo(ctx, app.Config)
	if ok, err := vStore.Ping(ctx); !ok {
		log.Fatal(err.Error())
	}
	vInfo := info.NewInfo(app.Config.SecretKey, vStore)
	appHandler := handler.NewHandler(vInfo)
	appRouter := router.NewRouter(appHandler)
	appServer := server.NewServer(app.Config.Listen, appRouter)

	wg := &sync.WaitGroup{}
	wg.Add(1)

	log.Infof("listen at: %s", appServer.Addr())
	go app.Serve(ctx, wg, appServer)

	<-ctx.Done()
	cancel()
	wg.Wait()
}
