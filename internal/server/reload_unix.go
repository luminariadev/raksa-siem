//go:build !windows

package server

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func registerReloadSignal(ctx context.Context, onReload func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				if onReload != nil {
					onReload()
				}
			}
		}
	}()
}
