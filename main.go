package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Event holds a timestamped log message
type Event struct {
    Timestamp string `json:"timestamp"`
    Message   string `json:"message"`
}

// startProbe launches cmdName with args and streams each stdout line into out.
// It stops the subprocess when ctx is cancelled.
func startProbe(ctx context.Context, out chan<- string, cmdName string, args ...string) error {
    cmd := exec.CommandContext(ctx, cmdName, args...)
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return err
    }
    cmd.Stderr = cmd.Stdout

    if err := cmd.Start(); err != nil {
        return err
    }

    // read lines
    go func() {
        defer cmd.Wait()
        scanner := bufio.NewScanner(stdout)
        for scanner.Scan() {
            out <- scanner.Text()
        }
        if err := scanner.Err(); err != nil {
            log.Printf("scanner error for %s: %v", cmdName, err)
        }
    }()

    // kill on context cancel
    go func() {
        <-ctx.Done()
        _ = cmd.Process.Signal(syscall.SIGINT)
    }()

    return nil
}

func main() {
    // catch Ctrl-C
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    ctx, cancel := context.WithCancel(context.Background())

    // single channel for all probes
    rawCh := make(chan string)

    // probes: plain names, no -T
    probes := [][]string{
        {"execsnoop"},
        {"tcpconnect"},
        {"opensnoop"},
    }
    for _, p := range probes {
        cmd, args := p[0], p[1:]
        if err := startProbe(ctx, rawCh, cmd, args...); err != nil {
            log.Fatalf("failed to start %s: %v", cmd, err)
        }
    }

    // consumer: read raw lines, timestamp in Go, emit JSON
    go func() {
        for line := range rawCh {
            ev := Event{
                Timestamp: time.Now().UTC().Format(time.RFC3339),
                Message:   strings.TrimSpace(line),
            }
            b, err := json.Marshal(ev)
            if err != nil {
                log.Printf("json marshal error: %v", err)
                continue
            }
            fmt.Println(string(b))
        }
    }()

    // wait for interrupt
    <-sigs
    log.Println("shutting down probes…")
    cancel()
    // give all goroutines a moment to finish
    time.Sleep(1 * time.Second)
    close(rawCh)
    log.Println("done")
}
