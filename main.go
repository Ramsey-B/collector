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

type Batch struct {
	Timestamp time.Time `json:"timestamp"`
	Events    []string   `json:"events"`
}

func must(cmd *exec.Cmd) {
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("command %v failed: %v\n%s", cmd.Args, err, out)
	}
}

func main() {
	interval := flag.Duration("interval", 5*time.Second, "collection window")
	key := flag.String("key", "collector", "audit key to tag rules with")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("must be run as root")
	}

	rules := [][]string{
		{"-a", "exit,always", "-F", "arch=b64", "-S", "execve", "-F", "key=" + *key},
		{"-a", "exit,always", "-F", "arch=b64", "-S", "openat", "-F", "key=" + *key},
		{"-a", "exit,always", "-F", "arch=b64", "-S", "connect", "-F", "key=" + *key},
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
			"-m", "SYSCALL,PATH,SOCKADDR",
			"-k", *key,
			"--start", "recent",
		).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ausearch error: %v\n%s", err, out)
		}

		// parse each non-empty line into an Event
		lines := strings.Split(string(out), "\n")

		// wrap into a batch and emit as JSON
		batch := Batch{Timestamp: time.Now().UTC(), Events: lines}
		enc, err := json.Marshal(batch)
		if err != nil {
			log.Fatalf("json.Marshal: %v", err)
		}
		fmt.Println(string(enc))

		// tear down rules for next cycle
		must(exec.Command("auditctl", "-D"))
	}
}
