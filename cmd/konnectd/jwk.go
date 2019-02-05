/*
 * Copyright 2019 Kopano and its licensors
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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"
)

func commandJwkFromPem() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwk-from-pem [key.pem]",
		Short: "Create JSON Web Key from PEM key file",
		Run: func(cmd *cobra.Command, args []string) {
			if err := jwkFromPem(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().String("kid", "", "Key ID kid")
	cmd.Flags().String("use", "sig", "Key usage use (required)")
	cmd.Flags().Bool("yaml", false, "Output JWK as YAML")

	return cmd
}

func jwkFromPem(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		cmd.Help()
		os.Exit(2)
	}

	kid, _ := cmd.Flags().GetString("kid")
	use, _ := cmd.Flags().GetString("sig")
	asYaml, _ := cmd.Flags().GetBool("yaml")
	fn := args[0]

	key, err := func() (interface{}, error) {
		signer, err := loadSignerFromFile(fn)
		if err == nil {
			return signer, nil
		}
		validator, err := loadValidatorFromFile(fn)
		if err == nil {
			return validator, nil
		}

		return nil, err
	}()
	if err != nil {
		return fmt.Errorf("failed to load pem file: %v", err)
	}

	if kid == "" {
		// Use file name as kid if no kid was given.
		_, fn := filepath.Split(fn)
		kid = strings.TrimSuffix(fn, filepath.Ext(fn))
	}

	priv := jose.JSONWebKey{Key: key, KeyID: kid, Use: use}
	if !priv.Valid() {
		return fmt.Errorf("parsed key is not valid")
	}

	privJSON, err := priv.MarshalJSON()
	if err != nil {
		return fmt.Errorf("error marshaling key as JSON: %v", err)
	}

	if asYaml {
		privYAML, err := yaml.JSONToYAML(privJSON)
		if err != nil {
			return fmt.Errorf("error marshalling key as YAML: %v", err)
		}
		fmt.Println(string(privYAML))
	} else {
		var prettyPrivJSON bytes.Buffer
		err = json.Indent(&prettyPrivJSON, privJSON, "", "\t")
		if err != nil {
			return fmt.Errorf("error marshalling key as pretty JSON: %v", err)
		}
		fmt.Println(prettyPrivJSON.String())
	}

	return nil
}
