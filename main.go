package main

import (
	"bufio"
	"bytes"
	"context"
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
	"sync"
	"time"

	"slices"

	"github.com/google/uuid"
)

type Event struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

type Batch struct {
	Timestamp time.Time `json:"timestamp"`
	Logs      []Event   `json:"logs"`
}

var client = http.DefaultClient

func postJSON(endpoint string, payload any) error {
	reqID := uuid.New().String()
	log.Printf("sending %d logs to %s (reqID: %s)", len(payload.(Batch).Logs), endpoint, reqID)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		if err != io.EOF {
			return err
		}
	}
	if resp != nil {
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		log.Printf("logs sent with status: %s (reqID: %s)", resp.Status, reqID)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("bad status %s", resp.Status)
		}
	}
	log.Printf("logs sent (reqID: %s)", reqID)
	return nil
}

var msgRe = regexp.MustCompile(`msg=audit\\((\\d+\\.\\d+):\\d+\\)`)

func parseLine(line string) (Event, bool) {
	if line == "" {
		return Event{}, false
	}
	ev := Event{Message: line}
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, "type=") {
			ev.Type = strings.TrimPrefix(tok, "type=")
			break
		}
	}
	if m := msgRe.FindStringSubmatch(line); len(m) == 2 {
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			sec := int64(f)
			nsec := int64((f - float64(sec)) * 1e9)
			ev.Timestamp = time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano)
		}
	}

	// todo: figure out why some logs don't have a timestamp
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	return ev, true
}

func main() {
	flushSize := flag.Int("flush", 2048, "number of events before sending batch")
	key := flag.String("key", "collector", "audit key")
	endpoint := flag.String("endpoint", "http://127.0.0.1:3000/api/v1.0/logs", "POST target")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("must run as root")
	}

	// install audit rules once
	rules := [][]string{
		// record every execve
		{
			"-a", "exit,always",
			"-F", "arch=b64",
			"-S", "execve",
			"-F", "key=" + *key,
		},
		// record every openat under /etc (optional path filter)
		{
			"-a", "exit,always",
			"-F", "arch=b64",
			"-S", "openat",
			"-F", "dir=/etc", // only files in /etc
			"-F", "key=" + *key,
		},
		// record only IPv4 connect() syscalls
		{
			"-a", "exit,always",
			"-F", "arch=b64",
			"-S", "connect",
			"-F", "a2=2", // AF_INET only
			"-F", "key=" + *key,
		},
	}
	exec.Command("auditctl", "-D").Run()
	for _, r := range rules {
		exec.Command("auditctl", r...).Run()
	}
	log.Println("audit rules installed; tailing audit.log…")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tail := exec.CommandContext(ctx, "tail", "-F", "/var/log/audit/audit.log")
	pipe, _ := tail.StdoutPipe()
	if err := tail.Start(); err != nil {
		log.Fatalf("tail start: %v", err)
	}

	var mu sync.Mutex
	buf := make([]Event, 0, *flushSize)

	flush := func() {
		if len(buf) == 0 {
			return
		}
		batch := Batch{
			Timestamp: time.Now().UTC(),
			Logs:      slices.Clone(buf),
		}
		buf = buf[:0] // clear the buffer
		postJSON(*endpoint, batch)
	}

	sc := bufio.NewScanner(pipe)
	for sc.Scan() {
		if ev, ok := parseLine(sc.Text()); ok {
			mu.Lock()
			buf = append(buf, ev)
			if len(buf) >= *flushSize {
				flush()
			}
			mu.Unlock()
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("scanner error: %v", err)
	}
}
