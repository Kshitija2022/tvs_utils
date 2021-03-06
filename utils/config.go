package utils

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Database database
	Server   server
}

type database struct {
	Host     string
	Port     string
	Database string
	User     string
	Password string
	Secret   string
}
type server struct {
	Port string
}

func NewConfig() *Config {
	var conf Config
	if _, err := toml.DecodeFile("./infrastructure/config.toml", &conf); err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%#v\n", conf)
	return &conf
}
