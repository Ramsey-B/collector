package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

func must(cmd *exec.Cmd) {
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("command %v failed: %v\n%s", cmd.Args, err, out)
	}
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatalf("this program must be run as root")
	}

	// flag for the polling interval
	interval := flag.Duration("interval", 5*time.Second, "duration to collect events before fetching")
	flag.Parse()

	rulesArgs := [][]string{
		{"-a", "exit,always", "-F", "arch=b64", "-S", "execve"},
		{"-a", "exit,always", "-F", "arch=b64", "-S", "open"},
		{"-a", "exit,always", "-F", "arch=b64", "-S", "openat"},
		{"-a", "exit,always", "-F", "arch=b64", "-S", "connect"},
	}

	for {
		// 1) remove any existing rules
		must(exec.Command("auditctl", "-D"))

		// 2) install our short-lived rules
		for _, args := range rulesArgs {
			must(exec.Command("auditctl", args...))
		}

		time.Sleep(*interval)

		out, err := exec.Command(
			"ausearch",
			"--format", "raw",
			"--message", "EXECVE",  // execve records
			"--message", "PATH",    // open/openat records
			"--message", "CONNECT", // connect records
			"--start", "recent",
		).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ausearch error: %v\n%s", err, out)
		} else {
			fmt.Print(string(out))
		}

		must(exec.Command("auditctl", "-D"))
	}
}
