/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"fmt"

	azicli "github.com/permguard/permguard/internal/cli"
)

func main() {
	// Run the cli
	initializer, err := azicli.NewCommunityCliInitializer()
	if err != nil {
		panic(fmt.Sprintf("cli: error creating cli: %s.", err.Error()))
	}
	azicli.Run(initializer)
}
