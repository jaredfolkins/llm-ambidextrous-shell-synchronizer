package main

import (
	"sync"
	"testing"
	"time"
)

func TestSessionCommandCacheConcurrency(t *testing.T) {
	// Initialize the cache
	initSessionCache()

	// Create variables to track test data
	const numGoroutines = 100
	const numSessions = 10
	const numOperationsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Create channels for deadlock detection
	done := make(chan struct{})
	timeout := time.After(30 * time.Second)

	// Launch test in a separate goroutine with timeout protection
	go func() {
		// Launch multiple goroutines to simulate concurrent requests
		for i := 0; i < numGoroutines; i++ {
			go func(routineID int) {
				defer wg.Done()

				// Each goroutine performs operations on multiple sessions
				for j := 0; j < numOperationsPerGoroutine; j++ {
					// Choose a session (distribute workload across sessions)
					sessionID := (routineID + j) % numSessions
					session := "session" + string(rune('A'+sessionID))

					// Perform a mix of operations that could cause race conditions

					// 1. Check if command matches (read operation)
					lastCmdMatch(session, "test command")

					// 2. Update command cache (write operation)
					resp := &CmdSubmission{
						Type:     "test",
						IsCached: false,
						Session:  session,
						Ticket:   j + 1,
						Input:    "test command " + string(rune('A'+j%26)),
						Callback: "test callback",
					}
					updateLastCommandByTicketResponse(session, resp)

					// 3. Create a new response (read operation)
					NewCmdResponse(session, "test", j%2 == 0)

					// 4. Check the same session again (read after write)
					lastCmdMatch(session, "test command "+string(rune('A'+j%26)))
				}
			}(i)
		}

		// Wait for all goroutines to complete
		wg.Wait()
		close(done)
	}()

	// Check for deadlocks with timeout
	select {
	case <-done:
		// Test completed successfully
	case <-timeout:
		t.Fatal("Deadlock detected: test timed out")
	}

	// Verify cache consistency (optional)
	sessionCmdCache.mu.RLock()
	defer sessionCmdCache.mu.RUnlock()

	if len(sessionCmdCache.caches) > numSessions {
		t.Errorf("Expected at most %d sessions in cache, got %d", numSessions, len(sessionCmdCache.caches))
	}

	// Check each session's cache
	for session, cache := range sessionCmdCache.caches {
		if cache == nil {
			t.Errorf("Cache for session %s is nil", session)
		}
	}
}

// Test session isolation to ensure operations on one session don't affect others
func TestSessionIsolation(t *testing.T) {
	initSessionCache()

	// Set up two different sessions
	session1 := "isolation_test_1"
	session2 := "isolation_test_2"

	// Update session1
	resp1 := &CmdSubmission{
		Type:     "test",
		Ticket:   1,
		Session:  session1,
		Input:    "command for session 1",
		Callback: "callback1",
	}
	updateLastCommandByTicketResponse(session1, resp1)

	// Check that session2 is not affected
	isMatch := lastCmdMatch(session2, "command for session 1")
	if isMatch {
		t.Error("Command from session1 incorrectly matched in session2")
	}

	// Verify session1 properly updated
	isMatch = lastCmdMatch(session1, "command for session 1")
	if !isMatch {
		t.Error("Command not properly cached for session1")
	}
}

// Run these tests with: go test -race
