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
	"strconv"
	"strings"
	"syscall"
	"time"
)
type Event struct {
	Timestamp time.Time
	Message   string
}

func startProbe(ctx context.Context, cmdName string, args ...string) (<-chan Event, error) {
    cmd := exec.CommandContext(ctx, cmdName, args...)
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return nil, err
    }
    cmd.Stderr = cmd.Stdout // merge stderr so we don't lose failures

    if err := cmd.Start(); err != nil {
        return nil, err
    }

    events := make(chan Event)
    go func() {
        defer close(events)
        scanner := bufio.NewScanner(stdout)
        for scanner.Scan() {
            line := scanner.Text()
			parts := strings.Fields(line)
            if len(parts) < 2 {
                continue
            }
			ts := parts[0]
            message := strings.Join(parts[1:], " ")
            
            tsInt, _ := strconv.ParseInt(ts, 10, 64)
            timestamp := time.Unix(0, tsInt)
            
            events <- Event{
				Timestamp: timestamp,
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

    return events, nil
}

func main() {
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    // use a cancellable context so we can stop all probes at once
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // start the three probes
    execs, err := startProbe(ctx, "sudo", "execsnoop-bpfcc", "-T")
    if err != nil {
        log.Fatalf("execsnoop: %v", err)
    }
    conns, err := startProbe(ctx, "sudo", "tcpconnect-bpfcc", "-T")
    if err != nil {
        log.Fatalf("tcpconnect: %v", err)
    }
    opens, err := startProbe(ctx, "sudo", "opensnoop-bpfcc", "-T")
    if err != nil {
        log.Fatalf("opensnoop: %v", err)
    }

    // fan-in channel
    allEvents := make(chan Event)
    fanIn := func(src <-chan Event) {
        for ev := range src {
            allEvents <- ev
        }
    }
    go fanIn(execs)
    go fanIn(conns)
    go fanIn(opens)

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
