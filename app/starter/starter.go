package starter

import (
	"context"
	"log"
	"sync"

	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
	"github.com/sanya-spb/oneTimeInfo/internal/config"
	"github.com/sanya-spb/oneTimeInfo/pkg/version"
)

// application struct
type App struct {
	Info    *info.Info
	Version version.AppVersion
	Config  config.Config
}

// init for App
func NewApp(store info.InfoStore) (*App, error) {
	app := &App{
		Version: *version.Version,
		Config:  *config.NewConfig(),
	}
	return app, nil
}

type HTTPServer interface {
	Start(info *info.Info)
	Stop()
}

// start service
func (app *App) Serve(ctx context.Context, wg *sync.WaitGroup, hs HTTPServer) {
	defer wg.Done()
	hs.Start(app.Info)
	<-ctx.Done()
	hs.Stop()
}

// print welcome message
func (app *App) Welcome() {
	log.Printf("Starting otin-backend!\n\nVersion: %s [%s@%s]\nCopyright: %s\n\n", app.Version.Version, app.Version.Commit, app.Version.BuildTime, app.Version.Copyright)
	// log.Printf("Config dump: %+v\n", app.Config)
}
