package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical/plugin"

	splunk "github.com/splunk/vault-plugin-splunk"
)

var (
	version   string
	goVersion string
)

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	printVersion := flags.Bool("version", false, "Prints version")

	// all plugins ignore Parse errors
	// #nosec G104
	flags.Parse(os.Args[1:])

	switch {
	case *printVersion:
		fmt.Printf("%s %s (golang %s)\n", os.Args[0], version, goVersion)
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
