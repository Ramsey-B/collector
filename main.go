package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Event struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"` // formatted RFC3339Nano
	Raw       string `json:"raw"`
}

type Batch struct {
	Timestamp time.Time `json:"timestamp"`
	Logs    []Event   `json:"logs"`
}

func must(cmd *exec.Cmd) {
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("command %v failed: %v\n%s", cmd.Args, err, out)
	}
}

var client = http.DefaultClient

func sendLogs(endpoint string, batch Batch) error {
	fmt.Println(batch)
	enc, err := json.Marshal(batch)
	if err != nil {
		log.Fatalf("json.Marshal: %v", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(enc))
	if err != nil {
		log.Printf("creating request failed: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
    if err != nil {
        // ignore EOF on empty response
        if err == io.EOF {
            log.Printf("warning: EOF from server, treating as success")
        } else {
            return fmt.Errorf("sending request: %w", err)
        }
    }
    if resp != nil {
        defer resp.Body.Close()
        // read and discard body so connection can be reused
        io.Copy(io.Discard, resp.Body)

        // accept any 2xx
        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
            log.Printf("request failed: %s", resp.Status)
        }
    }

	return nil
}

var msgRe = regexp.MustCompile(`msg=audit\((\d+\.\d+):\d+\)`)

func parseEvent(line string) Event {
	ev := Event{Raw: line}

	// extract type=
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, "type=") {
			ev.Type = strings.TrimPrefix(tok, "type=")
		}
	}

	// extract and parse the timestamp from msg=audit(...)
	if m := msgRe.FindStringSubmatch(line); len(m) == 2 {
		// m[1] is like "1715703605.123456789"
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			sec := int64(f)
			nsec := int64((f - float64(sec)) * 1e9)
			t := time.Unix(sec, nsec).UTC()
			ev.Timestamp = t.Format(time.RFC3339Nano)
		}
	}

	return ev
}


func main() {
	interval := flag.Duration("interval", 5*time.Second, "collection window")
	key := flag.String("key", "collector", "audit key to tag rules with")
	endpoint := flag.String("endpoint", "http://127.0.0.1:3000/api/v1.0/logs", "HTTP endpoint to POST batches to")
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
			log.Fatalf("ausearch error: %v\n%s", err, out)
		}

		// parse each non-empty line into an Event
		lines := strings.Split(string(out), "\n")
		events := make([]Event, 0, len(lines))
		for _, line := range lines {
			if line == "" {
				continue
			}
			events = append(events, parseEvent(line))
		}

		// wrap into a batch and emit as JSON
		batch := Batch{Timestamp: time.Now().UTC(), Logs: events}
		if err := sendLogs(*endpoint, batch); err != nil {
			log.Fatalf("sending logs failed: %v", err)
		}

		// tear down rules for next cycle
		must(exec.Command("auditctl", "-D"))
	}
}
