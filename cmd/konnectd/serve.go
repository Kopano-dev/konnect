/*
 * Copyright 2017 Kopano and its licensors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"stash.kopano.io/kc/konnect/server"
)

func commandServe() *cobra.Command {
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start server and listen for requests",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(cmd, args); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}
	serveCmd.Flags().String("listen", "127.0.0.1:8777", "TCP listen address")

	return serveCmd
}

func serve(cmd *cobra.Command, args []string) error {
	errCh := make(chan error, 2)
	signalCh := make(chan os.Signal)

	logger, err := newLogger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %v", err)
	}

	logger.Info("serve start")
	srv, err := server.NewServer(context.Background())
	if err != nil {
		return fmt.Errorf("failed to create server: %v", err)
	}

	listenAddr, _ := cmd.Flags().GetString("listen")
	logger.Infof("starting http listener on %s", listenAddr)
	go func() {
		listenErr := http.ListenAndServe(listenAddr, srv)
		errCh <- fmt.Errorf("failed to listen on %s with: %v", listenAddr, listenErr)
	}()

	// Wait for exit or error.
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err = <-errCh:
		// breaks
	case reason := <-signalCh:
		logger.Infof("signal: %s", reason)
		// breaks
	}

	return err
}
