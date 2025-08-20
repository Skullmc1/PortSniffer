package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// ScanResult holds port scan results
type ScanResult struct {
	Port   int    `json:"port"`
	Status string `json:"status"`
}

func main() {
	http.HandleFunc("/", serveHTML)
	http.HandleFunc("/scan", handleScan)

	fmt.Println("PortSniffer server listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func serveHTML(w http.ResponseWriter, r *http.Request) {
	html := `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>PortSniffer</title>
		<style>
			:root {
				--dark-bg: #1c1c1c;
				--primary-dark: #2c2c2c;
				--secondary-dark: #3a3a3a;
				--text-light: #e0e0e0;
				--accent-color: #00ffc8;
				--open-color: #00ff00;
				--closed-color: #ff4444;
			}
			* {
				margin: 0;
				padding: 0;
				box-sizing: border-box;
			}
			body {
				background-color: var(--dark-bg);
				color: var(--text-light);
				font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
				display: flex;
				flex-direction: column;
				align-items: center;
				min-height: 100vh;
				padding: 20px;
			}
			.header {
				width: 100%;
				max-width: 800px;
				padding: 10px 0;
				display: flex;
				justify-content: space-between;
				align-items: center;
			}
			.header h1 {
				font-size: 2.5em;
				color: var(--accent-color);
				text-shadow: 0 0 10px var(--accent-color);
			}
			.container {
				background-color: var(--primary-dark);
				border-radius: 10px;
				padding: 25px;
				width: 100%;
				max-width: 800px;
				margin: 20px 0;
				box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5);
			}
			.input-group {
				display: flex;
				gap: 10px;
				margin-bottom: 20px;
			}
			.input-group label {
				font-weight: bold;
				align-self: center;
			}
			.input-group input {
				flex: 1;
				padding: 10px;
				background-color: var(--secondary-dark);
				color: var(--text-light);
				border: 1px solid #555;
				border-radius: 5px;
				font-size: 1em;
			}
			.input-group button {
				padding: 10px 20px;
				background-color: var(--accent-color);
				color: var(--primary-dark);
				border: none;
				border-radius: 5px;
				cursor: pointer;
				font-weight: bold;
				transition: background-color 0.3s;
			}
			.input-group button:hover {
				background-color: #00e6b8;
			}
			#results-container {
				background-color: var(--secondary-dark);
				border-radius: 5px;
				padding: 15px;
				height: 300px;
				overflow-y: auto;
			}
			.results-list li {
				padding: 8px 0;
				border-bottom: 1px solid #444;
				display: flex;
				justify-content: space-between;
				align-items: center;
			}
			.status-open {
				color: var(--open-color);
				font-weight: bold;
			}
			.status-closed {
				color: var(--closed-color);
				font-weight: bold;
			}
			.footer {
				margin-top: auto;
				padding: 20px 0;
				font-size: 0.9em;
				color: #888;
			}
		</style>
	</head>
	<body>
		<div class="header">
			<h1>PortSniffer</h1>
		</div>
		<div class="container">
			<div class="input-group">
				<label for="ip-input">Target IP/Host:</label>
				<input type="text" id="ip-input" value="localhost" placeholder="e.g., 127.0.0.1">
				<button onclick="startScan()">Scan Ports</button>
			</div>
			<div id="results-container">
				<ul id="results" class="results-list"></ul>
			</div>
		</div>
		<div class="footer">
			Made by Qclid
		</div>
		<script>
			async function startScan() {
				const ipInput = document.getElementById('ip-input');
				const target = ipInput.value || 'localhost';
				const resultsList = document.getElementById('results');
				
				// Clear previous results
				resultsList.innerHTML = '';
				
				// Add a "Scanning..." message
				resultsList.innerHTML = '<li>Scanning ' + target + '...</li>';

				try {
					const response = await fetch('/scan?target=' + target);
					const data = await response.json();
					
					resultsList.innerHTML = ''; // Clear the message
					
					if (data.length === 0) {
						resultsList.innerHTML = '<li>No open ports found on ' + target + '.</li>';
					} else {
						data.forEach(result => {
							const li = document.createElement('li');
							li.innerHTML = 'Port ' + result.port + ': <span class="status-' + result.status.toLowerCase() + '">' + result.status + '</span>';
							resultsList.appendChild(li);
						});
					}
				} catch (error) {
					resultsList.innerHTML = '<li>Error: Failed to fetch results.</li>';
					console.error('Scan error:', error);
				}
			}
		</script>
	</body>
	</html>
	`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		target = "localhost" // this will scan the machine that this runs on
	}

	timeout := 500 * time.Millisecond
	var wg sync.WaitGroup
	results := make(chan ScanResult, 1024)
	var mu sync.Mutex
	var openPorts []ScanResult

	for port := 1; port <= 65535; port++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", target, port)
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err == nil {
				conn.Close()
				results <- ScanResult{Port: port, Status: "Open"}
			}
		}(port)
	}

	go func() {
		for r := range results {
			mu.Lock()
			openPorts = append(openPorts, r)
			mu.Unlock()
		}
	}()

	wg.Wait()
	close(results)

	// Sort results by port number
	for i := 0; i < len(openPorts)-1; i++ {
		for j := i + 1; j < len(openPorts); j++ {
			if openPorts[i].Port > openPorts[j].Port {
				openPorts[i], openPorts[j] = openPorts[j], openPorts[i]
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(openPorts); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
