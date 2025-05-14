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
    body, err := json.Marshal(payload)
    if err != nil {
        return err
    }
    req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    if err != nil && err != io.EOF {
        return err
    }
    if resp != nil {
        defer resp.Body.Close()
        io.Copy(io.Discard, resp.Body)
        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
            return fmt.Errorf("bad status %s", resp.Status)
        }
    }
    return nil
}

var msgRe = regexp.MustCompile(`msg=audit\\((\\d+\\.\\d+):\\d+\\)`)

func parseLine(line string) (Event, bool) {
    if line == "" { return Event{}, false }
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
    return ev, true
}

func main() {
    interval := flag.Duration("interval", 5*time.Second, "batch interval")
    key      := flag.String("key", "collector", "audit key tag (unused in tail mode)")
    endpoint := flag.String("endpoint", "http://127.0.0.1:3000/api/v1.0/logs", "POST target")
    flag.Parse()

    if os.Geteuid() != 0 { log.Fatal("must run as root") }

    // install audit rules once
    rules := [][]string{{"-a","exit,always","-F","arch=b64","-S","execve","-F","key="+*key},{"-a","exit,always","-F","arch=b64","-S","openat","-F","key="+*key},{"-a","exit,always","-F","arch=b64","-S","connect","-F","key="+*key}}
    exec.Command("auditctl","-D").Run()
    for _, r := range rules { exec.Command("auditctl", r...).Run() }
    log.Println("audit rules installed; tailing /var/log/audit/audit.log")

    // tail -F the audit log
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    tailCmd := exec.CommandContext(ctx, "tail", "-F", "/var/log/audit/audit.log")
    pipe, _ := tailCmd.StdoutPipe()
    if err := tailCmd.Start(); err != nil { log.Fatalf("tail start: %v", err) }

    // shared buffer for lines
    var mu sync.Mutex
    buffer := make([]Event,0,128)

    go func() {
        sc := bufio.NewScanner(pipe)
        for sc.Scan() {
            if ev, ok := parseLine(sc.Text()); ok {
                mu.Lock()
                buffer = append(buffer, ev)
                mu.Unlock()
            }
        }
        if err := sc.Err(); err != nil {
            log.Printf("tail scanner error: %v", err)
        }
    }()

    ticker := time.NewTicker(*interval)
    defer ticker.Stop()

    for range ticker.C {
        mu.Lock()
        if len(buffer)==0 { mu.Unlock(); continue }
        batch := Batch{Timestamp: time.Now().UTC(), Logs: append([]Event(nil), buffer...)}
        buffer = buffer[:0]
        mu.Unlock()

        go func(b Batch){
            if err := postJSON(*endpoint, b); err != nil {
                log.Printf("post error: %v", err)
            }
        }(batch)
    }
}