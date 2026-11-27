//go:build windows

package server

import "context"

func registerReloadSignal(ctx context.Context, onReload func()) {
	_ = ctx
	_ = onReload
}
