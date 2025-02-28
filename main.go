package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv" // For .env support
	"github.com/russross/blackfriday/v2"
)

var (
	hashPassword string // Global variable for the hash password
	fqdn         string // Global variable for the FQDN
	port         string // Global variable for the port
	sessionsDir  string // Global variable for the sessions directory
	logger       = log.New(os.Stdout, "shellHandler: ", log.LstdFlags)
)

type TicketResponse struct {
	IsCached bool   `json:"cached"`
	Ticket   int    `json:"ticket"`
	Session  string `json:"session"`
	Input    string `json:"input"`
	Output   string `json:"output"`
}

type CmdSubmission struct {
	Type     string `json:"type"`
	IsCached bool   `json:"cached"`
	Ticket   int    `json:"ticket"`
	Session  string `json:"session"`
	Input    string `json:"input"`
	Callback string `json:"callback"`
}

type CmdResults struct {
	Type     string `json:"type"`
	Next     string `json:"next"`
	Ticket   int    `json:"ticket"`
	Session  string `json:"session"`
	Input    string `json:"input"`
	Output   string `json:"output"`
	Duration string `json:"duration"`
}

const (
	callback          = "%s/callback?hash=%s&session=%s&ticket=%d"
	errorMessage      = "An error occurred while processing your request."
	errHashMessage    = "Invalid or missing 'hash' parameter"
	errSessionMessage = "Invalid or missing 'session' parameter"
	errTicketMessage  = "Invalid or missing 'ticket' parameter"
	errCmdMessage     = "Invalid or missing 'cmd' parameter"
	errMethodMessage  = "Method not allowed"
	errServerMessage  = "Server error"
)

func tm(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()

		done := make(chan bool)
		go func() {
			h(w, r.WithContext(ctx))
			done <- true
		}()

		select {
		case <-done:
			return
		case <-ctx.Done():
			w.WriteHeader(http.StatusGatewayTimeout)
			msg := "Request timeout exceeded"
			writePlainMessage(w, msg)
			return
		}
	}
}

func main() {

	loadEnv()

	lastCommand = &CmdCache{}
	listenAddr := fmt.Sprintf(":%s", port)

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           nil, // uses default mux
		ReadTimeout:       120 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 20 * time.Second,
	}
	// Register handlers for the endpoints
	http.HandleFunc("/", tm(readmeHandler))
	http.HandleFunc("/shell", tm(shellHandler))
	http.HandleFunc("/history", tm(historyHandler))
	http.HandleFunc("/callback", tm(callbackHandler))
	http.HandleFunc("/context", tm(contextHandler))
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))
	// Start the server using the PORT from .env
	logger.Printf("Starting server with FQDN: %s on port %s", fqdn, port)
	err := server.ListenAndServe()
	if err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

func Callback(session string, ticket int) string {
	return fmt.Sprintf(callback, fqdn, hashPassword, session, ticket)
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		logger.Fatalf("Error loading .env file: %v", err)
	}

	syncValue := os.Getenv("SYNC")
	if syncValue == "" {
		logger.Printf("SYNC not set in .env file, defaulting to false")
		os.Setenv("SYNC", "false")
	}

	hashPassword = os.Getenv("HASH")
	fqdn = os.Getenv("FQDN")
	port = os.Getenv("PORT")
	sessionsDir = os.Getenv("SESSIONS_DIR")

	// Validate environment variables
	if len(hashPassword) < 32 {
		logger.Fatalf("HASH must be >= 32 characters: %d", len(hashPassword))
	}

	if fqdn == "" {
		logger.Fatalf("FQDN must be set in .env file")
	}

	if port == "" {
		logger.Fatalf("PORT must be set in .env file")
	}

	if sessionsDir == "" {
		sessionsDir = "sessions" // Default value if not set
		logger.Printf("SESSIONS_DIR not set, using default: %s", sessionsDir)
	}

	// Initialize sessions directory
	if err := os.MkdirAll(sessionsDir, 0755); err != nil {
		logger.Fatalf("Failed to initialize sessions directory: %v", err)
	}

}
func getNextTicket(sessionFolder string) (int, error) {
	// Create the session folder if it doesn't exist
	err := os.MkdirAll(sessionFolder, 0755)
	if err != nil {
		return 0, fmt.Errorf("failed to create session folder: %v", err)
	}

	// Read all files in the session folder
	files, err := os.ReadDir(sessionFolder)
	if err != nil {
		return 0, fmt.Errorf("failed to read session folder: %v", err)
	}

	// Find the highest ticket number
	maxTicket := 0
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".ticket" {
			numStr := strings.TrimSuffix(file.Name(), ".ticket")
			num, err := strconv.Atoi(numStr)
			if err == nil && num > maxTicket {
				maxTicket = num
			}
		}
	}

	// Return next ticket number
	return maxTicket + 1, nil
}

type JsonErr struct {
	Error string `json:"error"`
}

type JsonMsg struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func writePlainMessage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain")
	http.Error(w, msg, http.StatusOK)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if r.Method != http.MethodGet {
		writePlainMessage(w, errMethodMessage)
		return
	}

	// Validate the hash parameter
	ticket, err := strconv.Atoi(r.URL.Query().Get("ticket"))
	if err != nil {
		writePlainMessage(w, errTicketMessage)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		writePlainMessage(w, errHashMessage)
		return
	}

	// Check if session is provided in query parameters
	session := r.URL.Query().Get("session")
	if session == "" {
		writePlainMessage(w, errSessionMessage)
		return
	}

	// If session is provided, create the session directory if it doesn't exist
	sessionFolder := filepath.Join(sessionsDir, session)
	if _, err := os.Stat(sessionFolder); os.IsNotExist(err) {
		msg := fmt.Sprintf("Session %s does not exist", sessionFolder)
		logger.Printf("Session not found!  %s: %v", sessionFolder, err)
		writePlainMessage(w, msg)
		return
	}

	// Read all ticket files in the session
	file, err := os.ReadFile(filepath.Join(sessionsDir, session, fmt.Sprintf("%02d.ticket", ticket)))
	if err != nil {
		msg := fmt.Sprintf("Failed to read ticket file: %v", err)
		writePlainMessage(w, msg)
		return
	}

	if len(file) == 0 {
		msg := fmt.Sprintf("No output for ticket %d yet. Refresh the page after randomly waiting a 1-20 seconds!", ticket)
		writePlainMessage(w, msg)
		return
	}

	writePlainMessage(w, fmt.Sprintf("%s\n", file))
	return
}

func shellHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if r.Method != http.MethodGet {
		writePlainMessage(w, errMethodMessage)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		writePlainMessage(w, errHashMessage)
		return
	}

	// Check if session is provided in query parameters
	session := r.URL.Query().Get("session")
	if session == "" {
		writePlainMessage(w, errSessionMessage)
		return
	}

	// Get query parameters
	cmdParam := r.URL.Query().Get("cmd")
	if cmdParam == "" {
		writePlainMessage(w, errCmdMessage)
		return
	}

	// Determine the command to execute
	var inputCmd string
	if cmdParam != "" {
		var erru error
		inputCmd, erru = url.QueryUnescape(cmdParam)
		if erru != nil {
			msg := fmt.Sprintf("Failed to unescape command: %v", erru)
			logger.Printf("Failed to unescape command: %v", erru)
			writePlainMessage(w, msg)
			return
		}
	}

	// If session is provided, create the session directory if it doesn't exist
	sessionFolder := filepath.Join(sessionsDir, session)
	if _, err := os.Stat(sessionFolder); os.IsNotExist(err) {
		if err := os.MkdirAll(sessionFolder, 0755); err != nil {
			msg := fmt.Sprintf("Failed to create session directory %s: %v", sessionFolder, err)
			logger.Printf(msg)
			writePlainMessage(w, msg)
			return
		}
		logger.Printf("Created new session directory: %s", sessionFolder)
	}

	isCached := lastCmdMatch(inputCmd)
	if isCached {
		resp := NewCmdReponse(session, true)
		jsonResp, err := json.Marshal(resp)
		if err != nil {
			msg := fmt.Sprintf("Failed to marshal JSON response: %v", err)
			writePlainMessage(w, msg)
			return
		}
		fmt.Fprintf(w, string(jsonResp))
		return
	}

	// Get the next ticket number
	ticket, err := getNextTicket(sessionFolder)
	if err != nil {
		writePlainMessage(w, errTicketMessage)
		return
	}

	csr := &CmdSubmission{
		Type:     "asynchronous",
		Ticket:   ticket,
		Session:  session,
		Input:    inputCmd,
		IsCached: isCached,
		Callback: Callback(session, ticket),
	}

	updateLastCommandByTicketResponse(csr)

	// LOG

	forest := &Runnner{
		CmdSubmission: csr,
		Ticket:        ticket,
		SessionFolder: sessionFolder,
		InputCmd:      inputCmd,
	}

	logger.Printf("EXECUTING: %s : %s : %s\n", session, inputCmd, Callback(session, ticket))
	////
	//// insync!!!
	///
	if !shouldSync() {
		go func() {
			runner(w, r, forest, "asynchronous", session)
		}()
		writePlainCsr(w, csr)
		return
	}

	///
	/// insync!!!
	///
	cer, err := runner(w, r, forest, "synchronous", session)
	if err != nil {
		msg := fmt.Sprintf("Failed to execute command: %v", err)
		writePlainMessage(w, msg)
		return
	}

	writePlainCer(w, cer)
	return
}

func writePlainCsr(w http.ResponseWriter, csr *CmdSubmission) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, fmt.Sprintf("HELLO LLM, YOU SUBMITTED A REQUEST AND THESE ARE RESULTS!\n\n"))
	fmt.Fprintf(w, fmt.Sprintf("TYPE: %s\n\n", csr.Type))
	fmt.Fprintf(w, fmt.Sprintf("SESSION: %s\n\n", csr.Session))
	fmt.Fprintf(w, fmt.Sprintf("TICKET: %d\n\n", csr.Ticket))
	fmt.Fprintf(w, fmt.Sprintf("CALLBACK: %s\n\n", csr.Callback))
	fmt.Fprintf(w, fmt.Sprintf("INPUT:\n\n%s\n\n", csr.Input))
	fmt.Fprintf(w, fmt.Sprintf("IS_CACHED:\n\n%s\n\n", csr.IsCached))

}

func writePlainCer(w http.ResponseWriter, cer *CmdResults) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, fmt.Sprintf("HELLO LLM, YOU SUBMITTED A REQUEST AND THESE ARE RESULTS!\n\n"))
	fmt.Fprintf(w, fmt.Sprintf("TYPE: %s\n\n", cer.Type))
	fmt.Fprintf(w, fmt.Sprintf("SESSION: %s\n\n", cer.Session))
	fmt.Fprintf(w, fmt.Sprintf("TICKET: %d\n\n", cer.Ticket))
	fmt.Fprintf(w, fmt.Sprintf("DURATION: %s\n\n", cer.Duration))
	fmt.Fprintf(w, fmt.Sprintf("NEXT:\n\n%s\n\n", cer.Next))
	fmt.Fprintf(w, fmt.Sprintf("INPUT:\n\n%s\n\n", cer.Input))
	fmt.Fprintf(w, fmt.Sprintf("OUTPUT:\n\n%s\n\n", cer.Output))
}

type Runnner struct {
	Ticket        int
	SessionFolder string
	InputCmd      string
	CmdSubmission *CmdSubmission
}

func runner(w http.ResponseWriter, r *http.Request, runner *Runnner, typ string, session string) (*CmdResults, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Define output filename based on session and ticket
	outputFile := filepath.Join(runner.SessionFolder, fmt.Sprintf("%02d.ticket", runner.Ticket))
	file, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		msg := fmt.Sprintf("Failed to open output file %s: %v", outputFile, err)
		logger.Print(msg)
		//writePlainMessage(w, msg)
		//file.WriteString(msg)
		return nil, fmt.Errorf("%s", msg)
	}
	defer file.Close()
	start := time.Now()
	// Execute the command using a shell to preserve quotes and complex syntax
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", runner.InputCmd) // Use "cmd" /C on Windows if needed
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := fmt.Sprintf("Command execution failed : %s : %v", string(output), err)
		logger.Print(msg)
		// WARNING: don't return
		// falled through so we can write the error to file
	}

	cer := &CmdResults{}
	cer.Type = typ
	cer.Next = "This is your result. Review the Input & Output. You can now issue your next command to /shell"
	cer.Ticket = runner.Ticket
	cer.Session = session
	cer.Input = runner.InputCmd
	cer.Output = string(output)
	cer.Duration = time.Since(start).String()

	jsonResp, err := json.Marshal(cer)
	if err != nil {
		msg := fmt.Sprintf("Failed to marshal JSON response: %v", err)
		logger.Print(msg)
		//writePlainMessage(w, msg)
		file.WriteString(msg)
		return nil, fmt.Errorf("%s", msg)
	}

	_, writeErr := file.Write(jsonResp)
	if writeErr != nil {
		msg := fmt.Sprintf("Failed to write error to file: %v", writeErr)
		logger.Print(msg)
		file.WriteString(msg)
		//return
		return nil, fmt.Errorf("%s", msg)
	}
	return cer, nil
}

func historyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if r.Method != http.MethodGet {
		writePlainMessage(w, errMethodMessage)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		writePlainMessage(w, errHashMessage)
		return
	}

	// Check if session is provided in query parameters
	session := r.URL.Query().Get("session")
	if session == "" {
		writePlainMessage(w, errSessionMessage)
		return
	}

	// Check if session exists
	sessionPath := filepath.Join(sessionsDir, session)
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		msg := fmt.Sprintf("Session %s does not exist", session)
		writePlainMessage(w, msg)
		return
	}

	// Read all ticket files in the session
	files, err := os.ReadDir(sessionPath)
	if err != nil {
		msg := fmt.Sprintf("Failed to read session directory: %v", err)
		writePlainMessage(w, msg)
		return
	}

	// Sort files by ticket number
	tickets := make([]string, 0)
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".ticket" {
			tickets = append(tickets, file.Name())
		}
	}

	if len(tickets) == 0 {
		msg := fmt.Sprintf("No tickets found for session %s", session)
		writePlainMessage(w, msg)
		return
	}

	var responses []*CmdResults
	// Display content of all tickets
	for _, ticket := range tickets {
		content, err := os.ReadFile(filepath.Join(sessionPath, ticket))
		if err != nil {
			logger.Printf("Failed to read ticket %s: %v", ticket, err)
			continue
		}
		resp := &CmdResults{}
		err = json.Unmarshal(content, resp)
		if err != nil {
			logger.Printf("Failed to unmarshal JSON from ticket %s: %v", ticket, err)
			continue
		}

		responses = append(responses, resp)
	}

	for _, resp := range responses {
		fmt.Fprintf(w, "Ticket: %d\n", resp.Ticket)
		fmt.Fprintf(w, "Session: %s\n", resp.Session)
		fmt.Fprintf(w, "Duration: %s\n", resp.Duration)
		fmt.Fprintf(w, "Next: %s\n", resp.Next)
		fmt.Fprintf(w, "Input: %s\n", resp.Input)
		fmt.Fprintf(w, "Output: %s\n", resp.Output)
		fmt.Fprintf(w, "\n")
	}
	return
}

func readmeHandler(w http.ResponseWriter, r *http.Request) {
	// Only handle the root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Ensure the request is a GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the README.md file
	content, err := os.ReadFile("README.md")
	if err != nil {
		logger.Printf("Failed to read README.md: %v", err)
		http.Error(w, "Failed to read documentation", http.StatusInternalServerError)
		return
	}

	contentStr := strings.ReplaceAll(string(content), "{FQDN}", fqdn)

	// Convert markdown to HTML
	html := blackfriday.Run([]byte(contentStr))
	printHTML(w, string(html))
}

func contextHandler(w http.ResponseWriter, r *http.Request) {
	// Only handle the root path
	if r.URL.Path != "/context" {
		http.NotFound(w, r)
		return
	}

	// Ensure the request is a GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		http.Error(w, "Invalid or missing 'hash' parameter", http.StatusUnauthorized)
		return
	}

	// Read the README.md file
	content, err := os.ReadFile("CONTEXT.md")
	if err != nil {
		logger.Printf("Failed to read CONTEXT.md: %v", err)
		http.Error(w, "Failed to read documentation", http.StatusInternalServerError)
		return
	}

	contentStr := strings.ReplaceAll(string(content), "{FQDN}", fqdn)

	// Convert markdown to HTML
	html := blackfriday.Run([]byte(contentStr))
	printHTML(w, string(html))
}

func readMainGo() (string, error) {
	// Read the main.go file
	content, err := os.ReadFile("main.go")
	if err != nil {
		return "", fmt.Errorf("failed to read main.go: %v", err)
	}

	// Add code formatting
	return "## SOURCE CODE FOR LLM CONSUMPTION\n ```\n" + string(content) + "\n```", nil
}

func printHTML(w http.ResponseWriter, html string) {
	// Set content type to HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Get main.go content
	mainGoContent, err := readMainGo()
	if err != nil {
		logger.Printf("Failed to read main.go: %v", err)
		mainGoContent = "Error reading main.go"
	}
	code := blackfriday.Run([]byte(mainGoContent))
	// Write a basic HTML wrapper around the converted markdown
	fmt.Fprintf(w, `<!DOCTYPE html>
	<html>
	<head>
		<title>LLMASS - LLM Ambidextrous Shell Synchronizer</title>
		<link rel="stylesheet" href="/assets/style.css">
	</head>
	<body>
		<div class="main">
			<div class="header">
				<a class="header-link" href="/">
					<img src="/assets/logo.png" alt="LLMAS Logo" width="200" height="200">
				</a>
			</div>
			<div class="content">
			%s
			%s
			</div>
		</div>
	</body>
	</html>`, html, code)
}

type CmdCache struct {
	Ticket   int
	Input    string
	Callback string
	IsCached bool
	Time     time.Time
	mu       sync.Mutex
}

var lastCommand *CmdCache

func lastCmdMatch(command string) bool {
	lastCommand.mu.Lock()
	defer lastCommand.mu.Unlock()
	if lastCommand != nil && lastCommand.Input == command && time.Since(lastCommand.Time) < time.Minute {
		return true
	}
	return false
}
func updateLastCommandByTicketResponse(resp *CmdSubmission) {
	lastCommand.mu.Lock()
	defer lastCommand.mu.Unlock()
	lastCommand.Callback = resp.Callback
	lastCommand.IsCached = resp.IsCached
	lastCommand.Input = resp.Input
	lastCommand.Ticket = resp.Ticket
	lastCommand.Time = time.Now()
}

func NewCmdReponse(session string, isCached bool) *CmdSubmission {
	lastCommand.mu.Lock()
	defer lastCommand.mu.Unlock()
	return &CmdSubmission{
		Type:     "submission",
		IsCached: isCached,
		Session:  session,
		Ticket:   lastCommand.Ticket,
		Input:    lastCommand.Input,
		Callback: lastCommand.Callback,
	}
}

func shouldSync() bool {
	if len(os.Getenv("SYNC")) == 0 {
		panic("SYNC env variable is not set")
	}

	if os.Getenv("SYNC") == "true" {
		return true
	}
	return false
}
