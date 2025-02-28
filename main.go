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
			writeJsonError(w, msg)
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

func writeJsonMsg(w http.ResponseWriter, status, msg string) {
	w.Header().Set("Content-Type", "application/json")
	resp, err := json.Marshal(&JsonMsg{Status: status, Message: msg})
	if err != nil {
		logger.Printf("Failed to marshal JSON response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to marshal JSON response: %v", err), http.StatusInternalServerError)
		return
	}
	http.Error(w, string(resp), http.StatusOK)
}

func writeJsonError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	resp, err := json.Marshal(&JsonErr{Error: msg})
	if err != nil {
		logger.Printf("Failed to marshal JSON response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to marshal JSON response: %v", err), http.StatusInternalServerError)
		return
	}
	http.Error(w, string(resp), http.StatusMethodNotAllowed)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		writeJsonError(w, errMethodMessage)
		return
	}

	// Validate the hash parameter
	ticket, err := strconv.Atoi(r.URL.Query().Get("ticket"))
	if err != nil {
		writeJsonError(w, errTicketMessage)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		writeJsonError(w, errHashMessage)
		return
	}

	// Check if session is provided in query parameters
	session := r.URL.Query().Get("session")
	if session == "" {
		writeJsonError(w, errSessionMessage)
		return
	}

	// If session is provided, create the session directory if it doesn't exist
	sessionFolder := filepath.Join(sessionsDir, session)
	if _, err := os.Stat(sessionFolder); os.IsNotExist(err) {
		msg := fmt.Sprintf("Session %s does not exist", sessionFolder)
		logger.Printf("Session not found!  %s: %v", sessionFolder, err)
		writeJsonError(w, msg)
		return
	}

	// Read all ticket files in the session
	file, err := os.ReadFile(filepath.Join(sessionsDir, session, fmt.Sprintf("%02d.ticket", ticket)))
	if err != nil {
		msg := fmt.Sprintf("Failed to read ticket file: %v", err)
		writeJsonError(w, msg)
		return
	}

	if len(file) == 0 {
		msg := fmt.Sprintf("No output for ticket %d yet. Refresh the page after waiting a bit!", ticket)
		writeJsonMsg(w, "working", msg)
		return
	}

	fmt.Fprintf(w, "%s\n", file)
	return
}

func shellHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		writeJsonError(w, errMethodMessage)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		writeJsonError(w, errHashMessage)
		return
	}

	// Check if session is provided in query parameters
	session := r.URL.Query().Get("session")
	if session == "" {
		writeJsonError(w, errSessionMessage)
		return
	}

	// Get query parameters
	cmdParam := r.URL.Query().Get("cmd")
	if cmdParam == "" {
		writeJsonError(w, errCmdMessage)
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
			writeJsonError(w, msg)
			return
		}
	}

	// If session is provided, create the session directory if it doesn't exist
	sessionFolder := filepath.Join(sessionsDir, session)
	if _, err := os.Stat(sessionFolder); os.IsNotExist(err) {
		if err := os.MkdirAll(sessionFolder, 0755); err != nil {
			msg := fmt.Sprintf("Failed to create session directory %s: %v", sessionFolder, err)
			logger.Printf(msg)
			writeJsonError(w, msg)
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
			writeJsonError(w, msg)
			return
		}
		fmt.Fprintf(w, string(jsonResp))
		return
	}

	// Get the next ticket number
	ticket, err := getNextTicket(sessionFolder)
	if err != nil {
		writeJsonError(w, errTicketMessage)
		return
	}

	csr := &CmdSubmission{
		Type:     "submission",
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
		jsonResp, err := json.Marshal(csr)
		if err != nil {
			msg := fmt.Sprintf("Failed to marshal JSON response: %v", err)
			writeJsonError(w, msg)
			return
		}
		fmt.Fprintf(w, string(jsonResp))
		return
	}

	///
	/// insync!!!
	///
	cer, err := runner(w, r, forest, "synchronous", session)
	if err != nil {
		msg := fmt.Sprintf("Failed to execute command: %v", err)
		writeJsonError(w, msg)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, fmt.Sprintf("HELLO LLM, YOU SUBMITTED A REQUEST AND THESE ARE RESULTS!\n\n"))
	fmt.Fprintf(w, fmt.Sprintf("THIS IS THE TYPE: %s\n\n", cer.Type))
	fmt.Fprintf(w, fmt.Sprintf("THIS IS THE SESSION NAME TO SYNCRONIZE YOUR JUMPHOST ACROSS REQUESTS: %s\n\n", cer.Session))
	fmt.Fprintf(w, fmt.Sprintf("THIS IS THE TICKET NUMBER SO YOU CAN USE TO REFERENCE THIS SPECIFC COMMAND REQUEST: %d\n\n", cer.Ticket))
	fmt.Fprintf(w, fmt.Sprintf("THIS IS THE LENGTH OF TIME THE COMMAND TOOK TO RUN: %s\n\n", cer.Duration))
	fmt.Fprintf(w, fmt.Sprintf("THIS IS THE NEXT STEP YOU CAN TAKE:\n\n%s\n\n", cer.Next))
	fmt.Fprintf(w, fmt.Sprintf("THIS IS THE INPUT YOU SUBMITTED TO THE LLMASS JUMPHOST SERVER:\n\n%s\n\n", cer.Input))
	fmt.Fprintf(w, fmt.Sprintf("THIS IS THE OUTPUT YOU RECEIVED FROM THE COMMAND RUNNING ON THE LLMASS JUMPHOST SERVER:\n\n%s\n\n", cer.Output))
	return
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
		//writeJsonError(w, msg)
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
		//writeJsonError(w, msg)
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
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		writeJsonError(w, errMethodMessage)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		writeJsonError(w, errHashMessage)
		return
	}

	// Check if session is provided in query parameters
	session := r.URL.Query().Get("session")
	if session == "" {
		writeJsonError(w, errSessionMessage)
		return
	}

	// Check if session exists
	sessionPath := filepath.Join(sessionsDir, session)
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		msg := fmt.Sprintf("Session %s does not exist", session)
		writeJsonError(w, msg)
		return
	}

	// Read all ticket files in the session
	files, err := os.ReadDir(sessionPath)
	if err != nil {
		msg := fmt.Sprintf("Failed to read session directory: %v", err)
		writeJsonError(w, msg)
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
		writeJsonError(w, msg)
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

	jsonRespones, err := json.Marshal(responses)
	if err != nil {
		msg := fmt.Sprintf("Failed to marshal JSON response: %v", err)
		writeJsonError(w, msg)
		return
	}

	fmt.Fprintf(w, string(jsonRespones))
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
