package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"

	"github.com/sanya-spb/oneTimeInfo/api/handler"
	"github.com/sanya-spb/oneTimeInfo/api/router"
	"github.com/sanya-spb/oneTimeInfo/api/server"
	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
	"github.com/sanya-spb/oneTimeInfo/app/starter"
	"github.com/sanya-spb/oneTimeInfo/db/memory/info/store"
)

var (
	lErr *log.Logger
	lOut *log.Logger
)

func main() {
	store := store.NewInfo()
	app, err := starter.NewApp(store)
	if err != nil {
		log.Fatalln(err.Error())
	}
	if _, err := os.Stat(filepath.Dir(app.Config.LogAccess)); os.IsNotExist(err) {
		log.Fatalln(err.Error())
	}
	if _, err := os.Stat(filepath.Dir(app.Config.LogErrors)); os.IsNotExist(err) {
		log.Fatalln(err.Error())
	}
	if fAccess, err := os.OpenFile(app.Config.LogAccess, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil {
		log.Fatalln(err.Error())
	} else {
		defer fAccess.Close()
		lOut = log.New(fAccess, "", log.LstdFlags)
		lOut.Println("run")
	}
	if fErrors, err := os.OpenFile(app.Config.LogErrors, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil {
		log.Fatalln(err.Error())
	} else {
		defer fErrors.Close()
		lErr = log.New(fErrors, "", log.LstdFlags)
		lErr.Println("run")
	}

	secretKeyBytes, err := base64.StdEncoding.DecodeString(app.Config.SecretKey)
	if err != nil {
		log.Fatalln(fmt.Errorf("secretKey format error: %s", err.Error()))
	}
	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)

	if len(secretKey) != 32 {
		log.Fatalln(errors.New("secretKey length error"))
	}

	app.Welcome()

	vInfo := info.NewInfo(store)
	appHandler := handler.NewHandler(vInfo)
	appRouter := router.NewRouter(secretKey, appHandler)
	appServer := server.NewServer(app.Config.Listen, appRouter)

	wg := &sync.WaitGroup{}
	wg.Add(1)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	log.Printf("listen at: %s\n", appServer.Addr())
	go app.Serve(ctx, wg, appServer)

	<-ctx.Done()
	cancel()
	wg.Wait()
}
