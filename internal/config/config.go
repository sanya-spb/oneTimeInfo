package config

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
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
				return fmt.Errorf("Unknown file format: %s", path)
			}
		}
	} else {
		return fmt.Errorf("The configuration file is missing: %s", path)
	}
	return nil
}

// Init config
func NewConfig(ctx context.Context, log *logrus.Logger) *Config {
	var result *Config = new(Config)
	flag.StringVar(&result.ConfigFile, "config", GetEnv("CONFIG", ""), "Configuration settings file")
	flag.StringVar(&result.SecretKeyBase64, "secret", GetEnv("SECRET", ""), "Secret key")
	flag.BoolVar(&result.Debug, "debug", GetEnvBool("DEBUG", false), "Output of detailed debugging information")
	flag.StringVar(&result.Listen, "listen", GetEnv("LISTEN", ":80"), "listen addr:port")
	flag.StringVar(&result.LogAccess, "log-access", GetEnv("LOG_ACCESS", ""), "Log file")
	flag.StringVar(&result.LogErrors, "log-errors", GetEnv("LOG_ERRORS", ""), "Log file for errors")
	// flag.Uint64Var(&result.FilterTimeout, "filter-timeout", GetEnvUInt("FILTER_TIMEOUT", 1000), "Timeout to filtering data, ms")
	flag.Parse()

	if result.ConfigFile != "" {
		if err := result.loadConfFile(result.ConfigFile); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
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
func GetEnvUInt(key string, defaultVal uint64) uint64 {
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
