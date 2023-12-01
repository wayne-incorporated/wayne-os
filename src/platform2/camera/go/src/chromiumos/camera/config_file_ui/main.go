// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"chromiumos/camera/config_file_ui/configs"
	"chromiumos/tast/shutil"
)

type optionsLookUpTable map[string]*configs.OptionDescriptor

type configEntry struct {
	configDesc *configs.ConfigDescriptor
	optionsLut optionsLookUpTable
}

func getRootDir() string {
	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	absPath, err := filepath.Abs(pwd)
	if err != nil {
		panic(err)
	}
	return absPath
}

func serve(httpServer *http.Server, shutdownChan chan bool) {
	const settingFilesDir = "setting_files/"
	files, err := ioutil.ReadDir(filepath.Join(getRootDir(), settingFilesDir))
	if err != nil {
		log.Fatal("Failed to load reloadable config setting files")
	}

	allConfigs := make(map[string]configEntry)
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		// Load the config descriptor.
		var desc configs.ConfigDescriptor
		fpath := filepath.Join(settingFilesDir, f.Name())
		if err := desc.LoadDescriptor(fpath); err != nil {
			log.Printf("Failed to load file %q as config descriptor: %s", fpath, err)
			continue
		}
		if err := desc.LoadDeviceSettings(); err != nil {
			log.Printf("Failed to load on-device settings: %s", err)
			continue
		}

		// Set up the options LUT.
		lut := make(optionsLookUpTable)
		for _, o := range desc.Options {
			lut[o.Key] = o
		}

		allConfigs[desc.Key] = configEntry{
			configDesc: &desc,
			optionsLut: lut,
		}
	}

	const jsDir = "js"
	const jsDirPattern = "/js/"
	const cssDir = "css"
	const cssDirPattern = "/css/"
	http.Handle(jsDirPattern, http.StripPrefix(jsDirPattern, http.FileServer(http.Dir(jsDir))))
	http.Handle(cssDirPattern, http.StripPrefix(cssDirPattern, http.FileServer(http.Dir(cssDir))))

	var rootPattern = "/"
	http.HandleFunc(rootPattern, func(w http.ResponseWriter, r *http.Request) {
		optionsHandler(w, r, allConfigs)
	})

	log.Printf("HTTP server serving on %q...", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("HTTP server error: %v", err)
	}
	log.Printf("HTTP server shutdown completed")

	shutdownChan <- true
}

func optionsHandler(w http.ResponseWriter, r *http.Request, cmap map[string]configEntry) {
	type configOptionsPostData struct {
		Config  string                 `json:"config,omitempty"`
		Options map[string]interface{} `json:"options,omitempty"`
	}

	if r.Method == http.MethodGet {
		tmpl := configs.LayoutTemplate()
		var confList []*configs.ConfigDescriptor
		for _, v := range cmap {
			confList = append(confList, v.configDesc)
		}
		tmpl.Execute(w, confList)
	} else if r.Method == http.MethodPost {
		var data configOptionsPostData
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
		}
		defer r.Body.Close()
		json.Unmarshal(body, &data)
		log.Printf("Received new %q option values:", data.Config)
		for key, value := range data.Options {
			if err := cmap[data.Config].optionsLut[key].Update(value.(string)); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			log.Printf("\t%q: %v", key, cmap[data.Config].optionsLut[key].Value)
		}
		if err := cmap[data.Config].configDesc.SaveDeviceSettings(); err != nil {
			log.Fatal("Failed to save settings: ", err)
		}
	}
}

func allowlistIptablesPort(port int) func() {
	var bin = "/sbin/iptables"
	var args = []string{"-A", "INPUT"}
	args = append(args, "-p", "tcp")
	args = append(args, "--dport", fmt.Sprintf("%v", port))
	args = append(args, "-j", "ACCEPT")
	log.Printf("Setting iptables: %s", shutil.EscapeSlice(args))
	cmd := exec.Command(bin, args...)
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to allowlist tcp:%v in iptables. Remote connection might not work.", port)
		return func() {}
	}

	return func() {
		var args = []string{"-D", "INPUT"}
		args = append(args, "-p", "tcp")
		args = append(args, "--dport", fmt.Sprintf("%v", port))
		args = append(args, "-j", "ACCEPT")
		log.Printf("Cleaning up iptables: %s", shutil.EscapeSlice(args))
		cmd := exec.Command(bin, args...)
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to remove tcp:%v in iptables", port)
		}
	}
}

// handleSignal handles SIGINT and SIGTERM and gracefully shutdown |httpServer|.
// This is to allow the deferred clean-up function to run properly when the
// process is terminated by the two signals.
func handleSignal(httpServer *http.Server) {
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("HTTP server shutdown on signal: %v", sig)
	httpServer.Shutdown(context.Background())
	close(sigChan)
}

func main() {
	hostFlag := flag.String("host", "0.0.0.0", "the config UI server IP address")
	portFlag := flag.Int("port", 9000, "the config UI server port")
	flag.Parse()

	cleanUp := allowlistIptablesPort(*portFlag)
	defer cleanUp()

	addr := fmt.Sprintf("%s:%v", *hostFlag, *portFlag)
	httpServer := &http.Server{
		Addr: addr,
	}
	shutdownChan := make(chan bool)
	go serve(httpServer, shutdownChan)
	go handleSignal(httpServer)

	// Waiting for HTTP server to gracefully shutdown.
	<-shutdownChan
	close(shutdownChan)
}
