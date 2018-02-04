package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"

	"github.com/nhooyr/tlsmuxd/internal/tlsmuxd"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var configPath = flag.String("config", "", "path to configuration file")
var logger *zap.Logger

func main() {
	flag.Parse()

	// Probably should not be creating a development logger but a production logger that logs in a human friendly format.
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	err = run()
	if err != nil {
		logger.Fatal("failed to run",
			zap.Error(err),
		)
	}
}

func run() error {
	pc, err := readConfig()
	if err != nil {
		return err
	}
	pc.Logger = logger

	p, err := tlsmuxd.NewProxy(pc)
	if err != nil {
		return err
	}
	return p.ListenAndServe()
}

func readConfig() (*tlsmuxd.ProxyConfig, error) {
	configBytes, err := ioutil.ReadFile(*configPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read config path %v", *configPath)
	}

	var pc tlsmuxd.ProxyConfig
	err = json.Unmarshal(configBytes, &pc)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode config.json")
	}
	return &pc, nil
}
