package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Initialize global configuration and components
	InitGlobals()
	
	// Create DNS server
	server, err := NewDNSServer()
	if err != nil {
		MainLog.Fatalf("Failed to create DNS server: %v", err)
	}
	defer server.Close()
	
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Start server in goroutine
	go func() {
		if err := server.Start(ctx); err != nil && err != context.Canceled {
			MainLog.Errorf("Server error: %v", err)
		}
	}()
	
	// Wait for shutdown signal
	<-sigChan
	MainLog.Info("Shutdown signal received, stopping server...")
	cancel()
	
	// Save caches before exit
	CacheDB.Save()
	NegativeCache.Save()
	
	MainLog.Info("Server shutdown complete")
}