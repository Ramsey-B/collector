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
)
type Event struct {
	Timestamp string `json:"timestamp"`
	Message   string    `json:"message"`
}

func startProbe(ctx context.Context, eventsChan chan<- Event, cmdName string, args ...string) error {
    cmd := exec.CommandContext(ctx, cmdName, args...)
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return err
    }
    cmd.Stderr = cmd.Stdout // merge stderr so we don't lose failures

    if err := cmd.Start(); err != nil {
        return err
    }

    go func() {
        defer close(eventsChan)
        scanner := bufio.NewScanner(stdout)
        for scanner.Scan() {
            line := scanner.Text()
			parts := strings.Fields(line)
            if len(parts) < 2 {
                continue
            }
			ts := parts[0]
            message := strings.Join(parts[1:], " ")
            
            // tsInt, _ := strconv.ParseInt(ts, 10, 64)
            // timestamp := time.Unix(0, tsInt)
            
            eventsChan <- Event{
				Timestamp: ts,
				Message: message,
			}
        }
        if err := scanner.Err(); err != nil {
            log.Printf("scanner error: %v", err)
        }
    }()

    // when context cancels, kill the process
    go func() {
        <-ctx.Done()
        _ = cmd.Process.Signal(syscall.SIGINT)
        cmd.Wait()
    }()

    return nil
}

func main() {
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    // use a cancellable context so we can stop all probes at once
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

	allEvents := make(chan Event) // <- channel to collect all events

    // start the three probes
    err := startProbe(ctx, allEvents, "sudo", "execsnoop-bpfcc", "-T")
    if err != nil {
        log.Fatalf("execsnoop: %v", err)
    }
    err = startProbe(ctx, allEvents, "sudo", "tcpconnect-bpfcc", "-T")
    if err != nil {
        log.Fatalf("tcpconnect: %v", err)
    }
    err = startProbe(ctx, allEvents, "sudo", "opensnoop-bpfcc", "-T")
    if err != nil {
        log.Fatalf("opensnoop: %v", err)
    }

    go func() {
        for ev := range allEvents {
            // TODO: preprocess (flatten fields, timestamp → ISO8601)
            // TODO: send to vector store / RAG pipeline
            b, _ := json.Marshal(ev)
            fmt.Println(string(b))
        }
    }()

    // wait for Ctrl-C or duration timeout
    <-sigs
    log.Println("shutting down probes…")
    cancel()
}
