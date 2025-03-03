package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"sort"
	//"encoding/json"
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

//go:embed README.md
var readmeContent []byte

//go:embed CONTEXT.md
var contextContent []byte

//go:embed assets/*
var assetsFS embed.FS

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
	B64Input string `json:"b64input,omitempty"` // Add this field
	Callback string `json:"callback"`
}

type CmdResults struct {
	Type     string `json:"type"`
	Next     string `json:"next"`
	Ticket   int    `json:"ticket"`
	Session  string `json:"session"`
	Input    string `json:"input"`
	B64Input string `json:"b64input,omitempty"`
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

	// Check for deadlocks with timeout
	initSessionCache()

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
	http.HandleFunc("/session", tm(sessionHandler))
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

func writePlainMessage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s\n", msg)
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
	b64CmdParam := r.URL.Query().Get("b64cmd")

	if cmdParam == "" && b64CmdParam == "" {
		writePlainMessage(w, "Invalid or missing 'cmd' or 'b64cmd' parameter")
		return
	}

	// Determine the command to execute
	var inputCmd string
	if b64CmdParam != "" {
		// Decode base64 command if provided
		decodedBytes, err := base64.StdEncoding.DecodeString(b64CmdParam)
		if err != nil {
			msg := fmt.Sprintf("Failed to decode base64 command: %v", err)
			logger.Printf(msg)
			writePlainMessage(w, msg)
			return
		}
		inputCmd = string(decodedBytes)
	} else {
		// Otherwise use regular cmd parameter
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

	isCached := lastCmdMatch(session, inputCmd)
	if isCached {
		resp := NewCmdResponse(session, "cached", true)
		writePlainCsr(w, resp)
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
		B64Input: b64CmdParam,
		IsCached: isCached,
		Callback: Callback(session, ticket),
	}

	updateLastCommandByTicketResponse(session, csr)

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
	fmt.Fprintf(w, makePlainCsr(csr))
}

func makePlainCsr(csr *CmdSubmission) string {
	res := fmt.Sprintf("HELLO LLM, YOU SUBMITTED A REQUEST AND THESE ARE RESULTS!\n\n")
	res += fmt.Sprintf("TYPE: %s\n\n", csr.Type)
	res += fmt.Sprintf("IS_CACHED:\n\n%v\n\n", csr.IsCached)
	res += fmt.Sprintf("SESSION: %s\n\n", csr.Session)
	res += fmt.Sprintf("TICKET: %d\n\n", csr.Ticket)
	res += fmt.Sprintf("CALLBACK: %s\n\n", csr.Callback)
	res += fmt.Sprintf("INPUT:\n\n%s\n\n", csr.Input)
	// Add this conditional section to include B64Input when present
	if csr.B64Input != "" {
		res += fmt.Sprintf("B64INPUT:\n\n%s\n\n", csr.B64Input)
	}
	return res
}

func writePlainCer(w http.ResponseWriter, cer *CmdResults) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, makePlainCer(cer))
}

func makePlainCer(cer *CmdResults) string {
	res := fmt.Sprintf("HELLO LLM, YOU SUBMITTED A REQUEST AND THESE ARE RESULTS!\n\n")
	res += fmt.Sprintf("TYPE: %s\n\n", cer.Type)
	res += fmt.Sprintf("SESSION: %s\n\n", cer.Session)
	res += fmt.Sprintf("TICKET: %d\n\n", cer.Ticket)
	res += fmt.Sprintf("DURATION: %s\n\n", cer.Duration)
	res += fmt.Sprintf("NEXT:\n\n%s\n\n", cer.Next)
	if cer.B64Input != "" {
		res += fmt.Sprintf("B64INPUT:\n\n%s\n\n", cer.B64Input)
	}
	res += fmt.Sprintf("INPUT:\n\n%s\n\n", cer.Input)
	res += fmt.Sprintf("OUTPUT:\n\n%s\n\n", cer.Output)
	return res
}

func writePlainCmd(w http.ResponseWriter) {
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
	cer := &CmdResults{
		Type:     typ,
		Next:     "This is your result. Review the Input & Output. You can now issue your next command to /shell",
		Ticket:   runner.Ticket,
		Session:  session,
		Input:    runner.InputCmd,
		B64Input: runner.CmdSubmission.B64Input, // Add this line
		Output:   string(output),
		Duration: time.Since(start).String(),
	}
	// Write the output to the file
	result := makePlainCer(cer)
	if _, err := file.WriteString(result); err != nil {
		logger.Printf("Failed to write to file %s: %v", outputFile, err)
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

	// Sort tickets numerically
	sort.Slice(tickets, func(i, j int) bool {
		numI, _ := strconv.Atoi(strings.TrimSuffix(tickets[i], ".ticket"))
		numJ, _ := strconv.Atoi(strings.TrimSuffix(tickets[j], ".ticket"))
		return numI < numJ
	})

	fmt.Fprintf(w, "HELLO LLM, HERE IS YOUR COMMAND HISTORY:\n\n")

	// Display content of all tickets with clear separation
	for _, ticket := range tickets {
		ticketNum := strings.TrimSuffix(ticket, ".ticket")
		fmt.Fprintf(w, "--- TICKET %s ---\n", ticketNum)

		content, err := os.ReadFile(filepath.Join(sessionPath, ticket))
		if err != nil {
			logger.Printf("Failed to read ticket %s: %v", ticket, err)
			fmt.Fprintf(w, "Error reading ticket: %v\n\n", err)
			continue
		}

		if len(content) > 0 {
			fmt.Fprintf(w, "%s\n\n", content)
		} else {
			fmt.Fprintf(w, "[Empty ticket]\n\n")
		}
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

	// Use the embedded README.md content
	contentStr := strings.ReplaceAll(string(readmeContent), "{FQDN}", fqdn)

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

	// Use the embedded CONTEXT.md content
	contentStr := strings.ReplaceAll(string(contextContent), "{FQDN}", fqdn)

	// Convert markdown to HTML
	html := blackfriday.Run([]byte(contentStr))
	printHTML(w, string(html))
}

func readMainGo() (string, error) {
	// Since main.go changes during development, we'll still read it from disk
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
		<link rel="icon" type="image/png" href="/assets/favicon-96x96.png" sizes="96x96" />
		<link rel="icon" type="image/svg+xml" href="/assets/favicon.svg" />
		<link rel="shortcut icon" href="/assets/favicon.ico" />
		<link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png" />
		<link rel="manifest" href="/assets/site.webmanifest" />
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

// SessionCommandCache maps session names to their respective command caches
type SessionCommandCache struct {
	mu     sync.RWMutex
	caches map[string]*CmdCache
}

var sessionCmdCache *SessionCommandCache

// Initialize the session cache
func initSessionCache() {
	sessionCmdCache = &SessionCommandCache{
		caches: make(map[string]*CmdCache),
	}
} // Get or create a command cache for a specific session

func (sc *SessionCommandCache) getSessionCache(session string) *CmdCache {
	sc.mu.RLock()
	cache, exists := sc.caches[session]
	sc.mu.RUnlock()

	if !exists {
		sc.mu.Lock()
		// Check again to avoid race condition
		if cache, exists = sc.caches[session]; !exists {
			cache = &CmdCache{mu: sync.Mutex{}}
			sc.caches[session] = cache
		}
		sc.mu.Unlock()
	}

	return cache
}

// Check if command matches last command for this session
func lastCmdMatch(session, command string) bool {
	cache := sessionCmdCache.getSessionCache(session)

	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.Input == command && time.Since(cache.Time) < time.Minute {
		return true
	}
	return false
}

// Update the session-specific cache with response
func updateLastCommandByTicketResponse(session string, resp *CmdSubmission) {
	cache := sessionCmdCache.getSessionCache(session)

	cache.mu.Lock()
	defer cache.mu.Unlock()

	cache.Callback = resp.Callback
	cache.IsCached = resp.IsCached
	cache.Input = resp.Input
	cache.Ticket = resp.Ticket
	cache.Time = time.Now()
}

// Create response from the session-specific cache
func NewCmdResponse(session, typ string, isCached bool) *CmdSubmission {
	cache := sessionCmdCache.getSessionCache(session)

	cache.mu.Lock()
	defer cache.mu.Unlock()

	return &CmdSubmission{
		Type:     typ,
		IsCached: isCached,
		Session:  session,
		Ticket:   cache.Ticket,
		Input:    cache.Input,
		Callback: cache.Callback,
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

func sessionHandler(w http.ResponseWriter, r *http.Request) {
	// Only handle the exact path
	if r.URL.Path != "/session" {
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

	// Get the name parameter
	nameParam := r.URL.Query().Get("name")
	if nameParam == "" {
		http.Error(w, "Missing 'name' parameter", http.StatusBadRequest)
		return
	}

	// Check if we should clear the session first
	clearParam := r.URL.Query().Get("clear")
	clearSession := clearParam == "true"

	sessionPath := filepath.Join(sessionsDir, nameParam)

	// Clear the session if requested
	if clearSession {
		// Remove from cache
		sessionCmdCache.mu.Lock()
		delete(sessionCmdCache.caches, nameParam)
		sessionCmdCache.mu.Unlock()

		// Remove directory
		if err := os.RemoveAll(sessionPath); err != nil {
			logger.Printf("Failed to remove session directory for %s: %v", nameParam, err)
			http.Error(w, "Failed to clear session", http.StatusInternalServerError)
			return
		}
	}

	// Create session directory if it doesn't exist
	if err := os.MkdirAll(sessionPath, 0755); err != nil {
		logger.Printf("Failed to create session directory for %s: %v", nameParam, err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Initialize the session in the cache
	sessionCmdCache.getSessionCache(nameParam)

	writePlainMessage(w, fmt.Sprintf("Session '%s' created successfully", nameParam))
}
