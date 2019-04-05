package main

/*
#include "enclave_app.h"
#cgo CFLAGS: -I/home/sgx/wave-verify-sgx/enclave_plus_app_src -I/home/sgx/wave-verify-sgx/utils -I/home/sgx/linux-sgx/linux/installer/bin/sgxsdk/include
#cgo LDFLAGS: /home/sgx/wave-verify-sgx/enclave_plus_app_src/libverify.so
*/
import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"net/http"
	_ "net/http/pprof"

	"github.com/BurntSushi/toml"
	"github.com/immesys/wave/consts"
	"github.com/immesys/wave/waved"
	"github.com/immesys/wavemq/core"
	"github.com/immesys/wavemq/server"
	logging "github.com/op/go-logging"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var lg = logging.MustGetLogger("main")

const WAVEMQPermissionSet = "\x4a\xd2\x3f\x5f\x6e\x73\x17\x38\x98\xef\x51\x8c\x6a\xe2\x7a\x7f\xcf\xf4\xfe\x9b\x86\xa3\xf1\xa2\x08\xc4\xde\x9e\xac\x95\x39\x6b"
const WAVEMQPublish = "publish"
const WAVEMQSubscribe = "subscribe"

//TODO test expiry gives unsub notifications
//TODO add "we are DR for" in config. Reject peer publish messages if we are not DR
//TODO persist messages if they have persist flag and we are DR
type Configuration struct {
	RoutingConfig core.RoutingConfig
	WaveConfig    waved.Configuration
	QueueConfig   core.QManagerConfig
	LocalConfig   server.LocalServerConfig
	PeerConfig    server.PeerServerConfig
}

func main() {

	if len(os.Args) != 2 {
		fmt.Printf("usage: wavemq config.toml\n")
		os.Exit(1)
	}

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		metricsAddr := "127.0.0.1:6060"
		if os.Getenv("METRICS_ADDRESS") != "" {
			metricsAddr = os.Getenv("METRICS_ADDRESS")
		}
		fmt.Printf("starting metrics on %q\n", metricsAddr)
		err := http.ListenAndServe(metricsAddr, nil)
		panic(err)
	}()

	file := os.Args[1]
	var conf Configuration
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		fmt.Printf("failed to load configuration: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("configuration loaded\n")

	consts.DefaultToUnrevoked = conf.WaveConfig.DefaultToUnrevoked
	qm, err := core.NewQManager(&conf.QueueConfig)
	if err != nil {
		fmt.Printf("failed to initialize queues: %v\n", err)
		os.Exit(1)
	}
	am, err := core.NewAuthModule(&conf.WaveConfig)
	if err != nil {
		fmt.Printf("failed to initialize auth: %v\n", err)
		os.Exit(1)
	}
	tm, err := core.NewTerminus(qm, am, &conf.RoutingConfig)
	if err != nil {
		fmt.Printf("failed to initialize routing: %v\n", err)
		os.Exit(1)
	}
	server.NewLocalServer(tm, am, &conf.LocalConfig)
	server.NewPeerServer(tm, am, &conf.PeerConfig)

	// initialize enclave
	fmt.Println("initializing enclave")
	if ret := C.init_enclave(); ret != 0 {
		fmt.Printf("failed to initialize enclave\n")
		os.Exit(1)
	}
	fmt.Println("done initializing enclave")

	sigchan := make(chan os.Signal, 30)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	<-sigchan
	fmt.Printf("SHUTTING DOWN\n")
	qm.Shutdown()
}
