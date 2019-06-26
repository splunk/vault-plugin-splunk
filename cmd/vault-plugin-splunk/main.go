package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical/plugin"

	splunk "github.com/splunk/vault-plugin-splunk"
)

// nolint: gochecknoglobals
var (
	version   = "dev"
	commit    = ""
	date      = ""
	goVersion = ""
)

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	printVersion := flags.Bool("version", false, "Prints version")

	// all plugins ignore Parse errors
	// #nosec G104
	// nolint:errcheck
	flags.Parse(os.Args[1:])

	printField := func(field, value string) {
		if field != "" && value != "" {
			fmt.Printf("%s: %s\n", field, value)
		}
	}
	switch {
	case *printVersion:
		printField("version", version)
		printField("commit", commit)
		printField("date", date)
		printField("go", goVersion)
		os.Exit(0)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: splunk.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
