package masque

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrWriterOverloaded = errors.New("HTTP/3 reliable writer queue overloaded")
	ErrWriterTimeout    = fmt.Errorf("HTTP/3 reliable writer: %w", context.DeadlineExceeded)
)

type reliableCommand struct {
	kind     uint64
	value    []byte
	packet   bool
	deadline time.Time
	done     func()
	bytes    int
	timer    *time.Timer
	finished bool
}

// ReliableWriter keeps stream-credit waits out of receive/control processing.
// Byte budgets include the in-flight command; deadlines include queue time.
type ReliableWriter struct {
	ctx         context.Context
	cancel      context.CancelFunc
	encoder     *Encoder
	deadline    func(time.Time) error
	abort       func()
	timeout     time.Duration
	control     chan *reliableCommand
	data        chan *reliableCommand
	finished    chan struct{}
	mu          sync.Mutex
	controlUsed int
	dataUsed    int
	err         error
}

func NewReliableWriter(ctx context.Context, encoder *Encoder, deadline func(time.Time) error, abort func(), timeout time.Duration) *ReliableWriter {
	ctx, cancel := context.WithCancel(ctx)
	w := &ReliableWriter{
		ctx: ctx, cancel: cancel, encoder: encoder, deadline: deadline,
		abort: abort, timeout: timeout, control: make(chan *reliableCommand, 8),
		data: make(chan *reliableCommand, 32), finished: make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *ReliableWriter) Control(kind uint64, value []byte, done func()) error {
	return w.enqueue(reliableCommand{kind: kind, value: value, done: done})
}

func (w *ReliableWriter) Packet(packet []byte, done func()) error {
	return w.enqueue(reliableCommand{value: packet, packet: true, done: done})
}

func (w *ReliableWriter) enqueue(command reliableCommand) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	queue, used, budget := w.control, &w.controlUsed, 64<<10
	if command.packet {
		queue, used, budget = w.data, &w.dataUsed, 256<<10
	}
	command.bytes = len(command.value) + 16
	if command.bytes > budget-*used {
		return ErrWriterOverloaded
	}
	command.deadline = time.Now().Add(w.timeout)
	command.value = append([]byte(nil), command.value...)
	command.timer = time.AfterFunc(w.timeout, func() {
		w.mu.Lock()
		expired := !command.finished && w.err == nil && w.ctx.Err() == nil
		if expired {
			w.err = ErrWriterTimeout
		}
		w.mu.Unlock()
		if expired {
			w.cancel()
		}
	})
	select {
	case queue <- &command:
		*used += command.bytes
		return nil
	default:
		command.finished = true
		command.timer.Stop()
		return ErrWriterOverloaded
	}
}

func (w *ReliableWriter) run() {
	defer close(w.finished)
	defer w.drain()
	stopped := make(chan struct{})
	stop := context.AfterFunc(w.ctx, func() {
		w.abort()
		close(stopped)
	})
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	for {
		var command *reliableCommand
		select {
		case <-w.ctx.Done():
			return
		default:
		}
		select {
		case command = <-w.control:
		default:
			select {
			case <-w.ctx.Done():
				return
			case command = <-w.control:
			case command = <-w.data:
			}
		}
		err := w.write(command)
		w.mu.Lock()
		command.finished = true
		command.timer.Stop()
		if command.packet {
			w.dataUsed -= command.bytes
		} else {
			w.controlUsed -= command.bytes
		}
		if err != nil && w.err == nil {
			w.err = err
		}
		w.mu.Unlock()
		if err != nil {
			w.abort()
			return
		}
		if command.done != nil {
			command.done()
		}
	}
}

func (w *ReliableWriter) write(command *reliableCommand) error {
	if !time.Now().Before(command.deadline) {
		return ErrWriterTimeout
	}
	if err := w.deadline(command.deadline); err != nil {
		return fmt.Errorf("set HTTP/3 reliable write deadline: %w", err)
	}
	var err error
	if command.packet {
		err = w.encoder.WriteIPPacket(command.value)
	} else {
		err = w.encoder.Write(command.kind, command.value)
	}
	if err != nil {
		var timeout interface{ Timeout() bool }
		if errors.As(err, &timeout) && timeout.Timeout() {
			return fmt.Errorf("%w: %w", ErrWriterTimeout, err)
		}
		return err
	}
	w.encoder.Flush()
	return nil
}

func (w *ReliableWriter) drain() {
	w.cancel()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, queue := range []chan *reliableCommand{w.control, w.data} {
		for {
			select {
			case command := <-queue:
				command.finished = true
				command.timer.Stop()
			default:
				goto next
			}
		}
	next:
	}
	w.controlUsed, w.dataUsed = 0, 0
}

func (w *ReliableWriter) Done() <-chan struct{} { return w.finished }

func (w *ReliableWriter) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	return w.ctx.Err()
}

func (w *ReliableWriter) Close() error {
	w.cancel()
	<-w.finished
	return w.Err()
}
