package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// Event is a generic map for the JSON output
type Event map[string]interface{}

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
            line := scanner.Bytes()
            var ev Event
            if err := json.Unmarshal(line, &ev); err != nil {
                log.Printf("failed to parse JSON: %v (line: %s)", err, line)
                continue
            }
            events <- ev
        }
        if err := scanner.Err(); err != nil && err != io.EOF {
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
    // catch Ctrl-C
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    // use a cancellable context so we can stop all probes at once
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // start the three probes
    execs, err := startProbe(ctx, "sudo", "execsnoop-bpfcc", "-jT")
    if err != nil {
        log.Fatalf("execsnoop: %v", err)
    }
    conns, err := startProbe(ctx, "sudo", "tcpconnect-bpfcc", "-jT")
    if err != nil {
        log.Fatalf("tcpconnect: %v", err)
    }
    opens, err := startProbe(ctx, "sudo", "opensnoop-bpfcc", "-jT")
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

    // optional: stop after a fixed duration
    go func() {
        time.Sleep(30 * time.Second)
        cancel()
    }()

    // main loop: process incoming events
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
    // give probes a moment to exit
    time.Sleep(1 * time.Second)
    log.Println("bye")
}
