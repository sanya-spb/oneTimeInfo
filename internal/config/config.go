package config

import (
	"context"
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

// configuration struct
type Config struct {
	ConfigFile      string
	Debug           bool   `yaml:"debug"`
	Listen          string `yaml:"listen"`
	SecretKeyBase64 string `yaml:"secret_key"`
	SecretKey       [32]byte
	LogAccess       string `yaml:"log_access"`
	LogErrors       string `yaml:"log_errors"`
	Admin           AdminConfig
	Store           StoreConfig
}

type AdminConfig struct {
	Login  string `yaml:"login"`
	Passwd string `yaml:"passwd"`
}

type StoreConfig struct {
	Address string `yaml:"address"`
	Port    uint   `yaml:"port"`
	User    string `yaml:"user"`
	Passwd  string `yaml:"passwd"`
	DBName  string `yaml:"db"`
}

// loading configuration parameters from a file
func (c *Config) loadConfFile(path string) error {
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		if f, err := os.Open(path); err != nil {
			return err
		} else {
			defer f.Close()

			switch ext := strings.ToLower(filepath.Ext(path)); ext {
			case ".yaml", ".yml":
				if err := yaml.NewDecoder(f).Decode(&c); err != nil {
					return err
				}
			default:
				return errors.New("Unknown file format")
			}
		}
	} else {
		return errors.New("The configuration file is missing")
	}
	return nil
}

// Init config
func NewConfig(ctx context.Context, log *logrus.Logger) *Config {
	var result *Config = new(Config)

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

	if port64 < 0 || port64 > 65535 {
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
	copy(result.SecretKey[:], secretKeyBytes)

	if len(result.SecretKey) != 32 {
		log.Fatal(errors.New("secretKey length error"))
	}

	return result
}

// Get uint value from ENV
func GetEnvUInt64(key string, defaultVal uint64) uint64 {
	if envVal, ok := os.LookupEnv(key); ok {
		if envBool, err := strconv.ParseUint(envVal, 10, 64); err == nil {
			return envBool
		}
	}
	return defaultVal
}

// Get string value from ENV
func GetEnv(key string, defaultVal string) string {
	if envVal, ok := os.LookupEnv(key); ok {
		return envVal
	}
	return defaultVal
}

// Get bool value from ENV
func GetEnvBool(key string, defaultVal bool) bool {
	if envVal, ok := os.LookupEnv(key); ok {
		if envBool, err := strconv.ParseBool(envVal); err == nil {
			return envBool
		}
	}
	return defaultVal
}
