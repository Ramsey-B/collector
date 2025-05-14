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

func startProbe(ctx context.Context, out chan<- string, cmdName string, args ...string) error {
    cmd := exec.CommandContext(ctx, cmdName, args...)
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return err
    }
    cmd.Stderr = cmd.Stdout

	// start the command
    if err := cmd.Start(); err != nil {
        return err
    }

	// read the output of the command
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

	// listen for the context to be cancelled
    go func() {
        <-ctx.Done()
        _ = cmd.Process.Signal(syscall.SIGINT)
    }()

    return nil
}

func main() {
    // Setup graceful shutdown
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Single channel for all probes
    rawCh := make(chan string)

    probes := [][]string{
        {"sudo", "execsnoop"},
        {"sudo", "tcpconnect"},
        {"sudo", "opensnoop"},
    }
    for _, p := range probes {
        cmd, args := p[0], p[1:]
        if err := startProbe(ctx, rawCh, cmd, args...); err != nil {
            log.Fatalf("failed to start %s: %v", args[0], err)
        }
    }

    go func() {
        for line := range rawCh {
            ts := time.Now().UTC().Format(time.RFC3339)
            ev := Event{Timestamp: ts, Message: strings.TrimSpace(line)}
            b, err := json.Marshal(ev)
            if err != nil {
                log.Printf("json marshal error: %v", err)
                continue
            }
            fmt.Println(string(b))
        }
    }()

    // Wait for interrupt
    <-sigs
    log.Println("Shutting down probes…")
    cancel()
    // Allow probes to exit
    time.Sleep(time.Second)
    close(rawCh)
    log.Println("Done.")
}