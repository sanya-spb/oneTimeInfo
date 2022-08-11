package starter

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
	"github.com/sanya-spb/oneTimeInfo/internal/config"
	"github.com/sanya-spb/oneTimeInfo/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
)

// application struct
type App struct {
	Info    *info.Info
	Version version.AppVersion
	Config  config.Config
	logger  *logrus.Logger
}

// init for App
func NewApp(logger *logrus.Logger) (*App, error) {
	logger.SetLevel(logrus.InfoLevel)
	logger.SetOutput(ioutil.Discard)
	logger.AddHook(&writer.Hook{ // Send logs with level higher than warning to stderr
		Writer: os.Stderr,
		LogLevels: []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
			logrus.WarnLevel,
		},
	})
	logger.AddHook(&writer.Hook{ // Send info and debug logs to stdout
		Writer: os.Stdout,
		LogLevels: []logrus.Level{
			logrus.InfoLevel,
			logrus.DebugLevel,
		},
	})

	app := &App{
		Version: *version.Version,
		Config:  *config.NewConfig(logger),
		logger:  logger,
	}

	if app.Config.Debug {
		app.logger.SetLevel(logrus.DebugLevel)
	}

	if len(app.Config.LogAccess) > 0 {
		fLog, err := os.OpenFile(app.Config.LogAccess, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("Can't open logfile %s", err.Error())
		}

		app.logger.AddHook(&writer.Hook{ // Send info and debug logs to stdout
			Writer: fLog,
			LogLevels: []logrus.Level{
				logrus.InfoLevel,
				logrus.DebugLevel,
			},
		})
	}

	if len(app.Config.LogErrors) > 0 {
		fLog, err := os.OpenFile(app.Config.LogErrors, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("Can't open logfile %s", err.Error())
		}

		app.logger.AddHook(&writer.Hook{ // Send logs with level higher than warning to stderr
			Writer: fLog,
			LogLevels: []logrus.Level{
				logrus.PanicLevel,
				logrus.FatalLevel,
				logrus.ErrorLevel,
				logrus.WarnLevel,
			},
		})
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
	app.logger.Info("Starting otin-backend!")
	app.logger.Debugf("Version dump: %#v", app.Version)
}
