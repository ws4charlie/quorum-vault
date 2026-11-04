package main

import "fmt"

func runScenario(cmd string, p *Party, m *Mux, args []string) error {
	return fmt.Errorf("unknown command %q", cmd)
}

func backupCmd(cmd string, args []string) error { return fmt.Errorf("todo") }
