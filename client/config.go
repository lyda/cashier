package client

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"os/user"
	"regexp"
)

// Config holds the client configuration.
type Config struct {
	CA                     string `mapstructure:"ca"`
	Keytype                string `mapstructure:"key_type"`
	Keysize                int    `mapstructure:"key_size"`
	Validity               string `mapstructure:"validity"`
	ValidateTLSCertificate bool   `mapstructure:"validate_tls_certificate"`
	PublicKey              string `mapstructure:"public_key"`
	PublicCert             string `mapstructure:"public_cert"`
}

func setDefaults() {
	viper.BindPFlag("ca", pflag.Lookup("ca"))
	viper.BindPFlag("key_type", pflag.Lookup("key_type"))
	viper.BindPFlag("key_size", pflag.Lookup("key_size"))
	viper.BindPFlag("validity", pflag.Lookup("validity"))
	viper.BindPFlag("public_key", pflag.Lookup("public_key"))
	viper.BindPFlag("public_cert", pflag.Lookup("public_cert"))
	viper.SetDefault("validateTLSCertificate", true)
}

// ExpandTilde expands ~ and ~user for a given path.
func ExpandTilde(path string) string {
	re := regexp.MustCompile("^~([^/]*)(/.*)")
	if m := re.FindStringSubmatch(path); len(m) > 0 {
		u, _ := user.Current()
		if m[1] != "" {
			u, _ = user.Lookup(m[1])
		}
		if u != nil {
			return u.HomeDir + m[2]
		}
	}
	return path
}

// ReadConfig reads the client configuration from a file into a Config struct.
func ReadConfig(path string) (*Config, error) {
	setDefaults()
	viper.SetConfigFile(path)
	viper.SetConfigType("hcl")
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	c := &Config{}
	if err := viper.Unmarshal(c); err != nil {
		return nil, err
	}
	return c, nil
}
