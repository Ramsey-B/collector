package main

import (
	"encoding/json"
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

type Batch struct {
	Timestamp time.Time       `json:"timestamp"`
	Events    json.RawMessage `json:"events"` // raw JSON array from ausearch
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatalf("this program must be run as root")
	}

	interval := flag.Duration("interval", 5*time.Second, "duration to collect events before fetching")
	flag.Parse()

	rulesArgs := [][]string{
		{"-a", "exit,always", "-F", "arch=b64", "-S", "execve"},
		{"-a", "exit,always", "-F", "arch=b64", "-S", "openat"},
		{"-a", "exit,always", "-F", "arch=b64", "-S", "connect"},
	}

	for {
		// clear out any old rules
		must(exec.Command("auditctl", "-D"))

		// install our short-lived rules
		for _, args := range rulesArgs {
			must(exec.Command("auditctl", args...))
		}

		// collect for the interval
		time.Sleep(*interval)

		// fetch JSON events from that window
		cmd := exec.Command(
			"ausearch",
			"--format", "json",      // JSON output
			"--message", "EXECVE",   // execve records
			"--message", "PATH",     // openat records
			"--message", "CONNECT",  // connect records
			"--start", "recent",     // only new ones
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ausearch error: %v\n%s", err, out)
		} else {
			// wrap in a timestamped batch
			batch := Batch{
				Timestamp: time.Now().UTC(),
				Events:    json.RawMessage(out),
			}
			enc, err := json.Marshal(batch)
			if err != nil {
				log.Fatalf("json marshal batch: %v", err)
			}
			fmt.Println(string(enc))
		}

		// remove rules before next interval
		must(exec.Command("auditctl", "-D"))
	}
}
