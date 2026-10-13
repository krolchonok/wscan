package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"wscan/internal/adscan"
	"wscan/internal/app"
	"wscan/internal/catalog"
	"wscan/internal/engine"
	"wscan/internal/storage"
	"wscan/internal/tui"
	"wscan/internal/web"
)

func webMode(args []string) (bool, bool, string, error) {
	if len(args) == 0 || args[0] != "serve" && args[0] != "--web" {
		return false, false, "", nil
	}
	tuiMode := args[0] == "--web"
	address := "127.0.0.1:8080"
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--listen":
			i++
			if i == len(args) {
				return true, tuiMode, "", fmt.Errorf("--listen требует IP:порт")
			}
			address = args[i]
		default:
			return true, tuiMode, "", fmt.Errorf("неизвестный параметр %q; wscan serve|--web [--listen 127.0.0.1:8080]", args[i])
		}
	}
	return true, tuiMode, address, nil
}
func runWeb(s *storage.Store, c *catalog.Catalog, e *engine.Engine, dir string, tuiMode bool, address string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	service, err := app.NewService(ctx, s, c, e, filepath.Join(dir, "exports", "ad"))
	if err != nil {
		return err
	}
	defer adscan.RestoreCoercionPorts()
	defer service.Close()
	server, err := web.Start(service, address)
	if err != nil {
		if tuiMode {
			fmt.Fprintln(os.Stderr, "Web не запущен:", err)
			return tui.RunWithService(ctx, s, c, e, dir, service, "")
		}
		return err
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Close(stop)
	}()
	server.EnableTerminal(func(ctx context.Context, width, height int) (web.Terminal, error) {
		return tui.StartWebTerminal(ctx, service, dir, width, height)
	})
	fmt.Println("Web:", server.URL())
	if tuiMode {
		return tui.RunWithService(ctx, s, c, e, dir, service, server.URL())
	}
	fmt.Println("Ctrl+C — завершить сервер и остановить задачи.")
	<-ctx.Done()
	return nil
}
