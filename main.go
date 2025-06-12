// Copyright 2023 the Drone Authors. All rights reserved.
// Use of this source code is governed by the Blue Oak Model License
// that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"github.com/harness-community/drone-github-app-token/plugin"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

func main() {
	fmt.Println("Starting Drone GitHub App Token plugin")

	var args plugin.Args
	if err := envconfig.Process("", &args); err != nil {
		logrus.WithError(err).Fatal("failed to parse plugin parameters")
	}

	if args.Level == "debug" {
		logrus.SetLevel(logrus.DebugLevel)
	} else if args.Level == "trace" {
		logrus.SetLevel(logrus.TraceLevel)
	}

	if err := plugin.Exec(context.Background(), args); err != nil {
		logrus.WithError(err).Fatal("plugin execution failed")
	}
}
