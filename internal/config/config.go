// Package config implements work with the configuration environment
package config

import (
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Config - main configuration struct
type Config struct {
	ConfigFile      string      `yaml:"-"`                    // path to config file
	Debug           bool        `yaml:"debug,omitempty"`      // turn on debug mode
	Listen          string      `yaml:"listen,omitempty"`     // listen port
	SecretKeyBase64 string      `yaml:"secret_key"`           // secret key in base64 format
	SecretKey       [32]byte    `yaml:"-"`                    // secret key
	LogAccess       string      `yaml:"log_access,omitempty"` // access log file
	LogErrors       string      `yaml:"log_errors,omitempty"` // error log file
	Admin           AdminConfig `yaml:"admin"`                // admin credentials
	Store           StoreConfig `yaml:"store"`                // DB connection params
}

// AdminConfig - credentials for administrative purposes
type AdminConfig struct {
	Login  string `yaml:"login"`  // admin login
	Passwd string `yaml:"passwd"` // admin password
}

// StoreConfig - parameters for connecting to the database
type StoreConfig struct {
	Address string `yaml:"address,omitempty"` // DB ip
	Port    uint   `yaml:"port,omitempty"`    // DB port
	User    string `yaml:"user"`              // DB username
	Passwd  string `yaml:"passwd"`            // DB password
	DBName  string `yaml:"db,omitempty"`      // DB name or ID
}

// loadConfFile loading configuration parameters from a file
func (c *Config) loadConfFile(path string) error {
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		var (
			f   *os.File
			err error
		)

		if f, err = os.Open(path); err != nil {
			return err
		}

		defer func(f *os.File) {
			_ = f.Close()
		}(f)

		switch ext := strings.ToLower(filepath.Ext(path)); ext {
		case ".yaml", ".yml":
			if err := yaml.NewDecoder(f).Decode(&c); err != nil {
				return err
			}
		default:
			return errors.New("unknown file format")
		}
	} else {
		return errors.New("the configuration file is missing")
	}

	return nil
}

// NewConfig initialization configuration
func NewConfig(log *logrus.Logger) *Config {
	var result = new(Config)

	flag.StringVar(&result.ConfigFile, "config", GetEnv("CONFIG", ""), "Config file")
	flag.StringVar(&result.SecretKeyBase64, "secret", GetEnv("SECRET", ""), "Secret key")
	flag.BoolVar(&result.Debug, "debug", GetEnvBool("DEBUG", false), "Output of detailed debugging information")
	flag.StringVar(&result.Listen, "listen", GetEnv("LISTEN", ":8080"), "listen addr:port")
	flag.StringVar(&result.LogAccess, "log-access", GetEnv("LOG_ACCESS", ""), "Log file")
	flag.StringVar(&result.LogErrors, "log-errors", GetEnv("LOG_ERRORS", ""), "Log file for errors")
	flag.StringVar(&result.Store.Address, "store-address", GetEnv("STORE_ADDRESS", "127.0.0.1"), "Store address")

	var port64 uint64

	flag.Uint64Var(&port64, "store-port", GetEnvUInt64("STORE_PORT", 6379), "Store port")
	flag.StringVar(&result.Store.User, "store-user", GetEnv("STORE_USER", ""), "Store user")
	flag.StringVar(&result.Store.Passwd, "store-passwd", GetEnv("STORE_PASSWD", ""), "Store password")
	flag.StringVar(&result.Store.DBName, "store-db", GetEnv("STORE_DB", ""), "Store DB name")
	flag.StringVar(&result.Admin.Login, "admin-login", GetEnv("ADMIN_LOGIN", ""), "Admin login")
	flag.StringVar(&result.Admin.Passwd, "admin-passwd", GetEnv("ADMIN_PASSWD", ""), "Admin password")
	flag.Parse()

	if result.ConfigFile != "" {
		if err := result.loadConfFile(result.ConfigFile); err != nil {
			log.Fatalf("Config file reading error: %s", err.Error())
		}
	}

	if port64 > 65535 {
		log.Fatal("port error")
	} else {
		result.Store.Port = uint(port64)
	}

	if result.SecretKeyBase64 == "" {
		log.Fatal("secret can not be null")
	}

	secretKeyBytes, err := base64.StdEncoding.DecodeString(result.SecretKeyBase64)
	if err != nil {
		log.Fatalf("secretKey format error: %s", err.Error())
	}

	if len(secretKeyBytes) != 32 {
		log.Fatal(errors.New("secretKey length error"))
	}

	copy(result.SecretKey[:], secretKeyBytes)

	return result
}

// GetEnvUInt64 get uint value from ENV
func GetEnvUInt64(key string, defaultVal uint64) uint64 {
	if envVal, ok := os.LookupEnv(key); ok {
		if envBool, err := strconv.ParseUint(envVal, 10, 64); err == nil {
			return envBool
		}
	}

	return defaultVal
}

// GetEnv get string value from ENV
func GetEnv(key string, defaultVal string) string {
	if envVal, ok := os.LookupEnv(key); ok {
		return envVal
	}

	return defaultVal
}

// GetEnvBool get bool value from ENV
func GetEnvBool(key string, defaultVal bool) bool {
	if envVal, ok := os.LookupEnv(key); ok {
		if envBool, err := strconv.ParseBool(envVal); err == nil {
			return envBool
		}
	}

	return defaultVal
}
