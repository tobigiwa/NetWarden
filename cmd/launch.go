/*
 * Copyright (c) 2023, Oluwatobi Giwa
 * All rights reserved.
 *
 * This software is licensed under the 3-Clause BSD License.
 * See the LICENSE file or visit https://opensource.org/license/bsd-3-clause/ for details.
 */
package cmd

import (
	nw "NetWarden/netwardendeamon"
	"sync"

	"github.com/spf13/cobra"
)

// launchCmd represents the launch command
var launchCmd = &cobra.Command{
	Use:   "launch",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {

		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			nw.Start()
			return
		}()

		wg.Wait()
	},
}

func init() {
	rootCmd.AddCommand(launchCmd)
}
