/*
 * Copyright (c) 2023, Oluwatobi Giwa
 * All rights reserved.
 *
 * This software is licensed under the 3-Clause BSD License.
 * See the LICENSE file or visit https://opensource.org/license/bsd-3-clause/ for details.
 */
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nw",
	Short: "A network monitoring tool",
	Long:  GetNWAsciiArt() + `Monitors and correlate network packets to process..., for now`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(GetNWAsciiArt(), "\n", "Monitors and correlate network packets to process..., for now")

	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.NetWarden.yaml)")
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func GetNWAsciiArt() string {
	s := ""
	s += "\u001b[33m    _   __          __  __     \u001b[0m\n"  // yellow
	s += "\u001b[33m   / | / /___  ____/ /_/ /_  __\u001b[0m\n"  // yellow
	s += "\u001b[31m  /  |/ / __ \\/ __  / / / / /\u001b[0m\n"   // red
	s += "\u001b[31m / /|  / /_/ / /_/ / / /_/ / \u001b[0m\n"    // red
	s += "\u001b[35m/_/ |_/\\____/\\__,_/_/\\__, /  \u001b[0m\n" // magenta
	s += "\u001b[35m                    /____/   \u001b[0m\n"    // magenta

	return s
}
