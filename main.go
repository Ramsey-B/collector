package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Event struct {
	// RawType is the value of the `type=` field (e.g. "SYSCALL" or "PATH")
	RawType string            `json:"type"`
	// Fields contains all the key→value pairs from the record
	Fields  map[string]string `json:"fields"`
}

type Batch struct {
	Timestamp time.Time `json:"timestamp"`
	Events    []Event   `json:"events"`
}

func must(cmd *exec.Cmd) {
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("command %v failed: %v\n%s", cmd.Args, err, out)
	}
}

// parseRecord turns a raw audit line like:
//   type=SYSCALL msg=audit(…): … syscall=59 exe="/usr/bin/ls" pid=1234 …
// into an Event{RawType:"SYSCALL", Fields: map[…]…}
func parseRecord(line string) Event {
	evt := Event{Fields: make(map[string]string)}
	parts := strings.Fields(line)
	for _, tok := range parts {
		if kv := strings.SplitN(tok, "=", 2); len(kv) == 2 {
			key, val := kv[0], kv[1]
			// strip surrounding quotes if present
			val = strings.Trim(val, `"`)
			evt.Fields[key] = val
			if key == "type" {
				evt.RawType = val
			}
		}
	}
	return evt
}

func main() {
	interval := flag.Duration("interval", 5*time.Second, "collection window")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("must be run as root")
	}

	rules := [][]string{
		{"-a", "exit,always", "-F", "arch=b64", "-S", "execve"},
		{"-a", "exit,always", "-F", "arch=b64", "-S", "openat"},
		{"-a", "exit,always", "-F", "arch=b64", "-S", "connect"},
	}

	for {
		// clear any old rules
		must(exec.Command("auditctl", "-D"))
		// install fresh rules
		for _, args := range rules {
			must(exec.Command("auditctl", args...))
		}

		time.Sleep(*interval)

		// fetch raw lines
		out, err := exec.Command(
			"ausearch",
			"--format", "raw",
			"--type", "SYSCALL",
			"--type", "PATH",
			"--type", "SOCKADDR",
			"--start", "recent",
		).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ausearch error: %v\n%s", err, out)
		}

		// parse each non-empty line into an Event
		lines := strings.Split(string(out), "\n")
		var evts []Event
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			evts = append(evts, parseRecord(ln))
		}

		// wrap into a batch and emit as JSON
		batch := Batch{Timestamp: time.Now().UTC(), Events: evts}
		enc, err := json.Marshal(batch)
		if err != nil {
			log.Fatalf("json.Marshal: %v", err)
		}
		fmt.Println(string(enc))

		// tear down rules for next cycle
		must(exec.Command("auditctl", "-D"))
	}
}
