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

package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"stash.kopano.io/kc/konnect/version"
)

// CommandVersion provides the commandline implementation for version.
func CommandVersion() *cobra.Command {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version and exit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(`\
Version: %s
Git Commit: %s
Built with: %s %s/%s
`,
				version.Version, version.GitCommit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}

	return versionCmd
}

func init() {
	RootCmd.AddCommand(CommandVersion())
}
