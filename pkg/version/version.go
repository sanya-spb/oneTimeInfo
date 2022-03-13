package version

// everything we need to know about our app
type AppVersion struct {
	Version   string
	Commit    string
	BuildTime string
	Copyright string
}

// global variable for export to main
var Version *AppVersion = new(AppVersion)

// set vars from Makefile via go build -ldflags "-s -w -X ..."
var (
	version   string
	commit    string
	buildTime string
	copyright string
)

// automating the loading of eggs into the basket
func init() {
	Version.Version = version
	Version.Commit = commit
	Version.BuildTime = buildTime
	Version.Copyright = copyright
}
