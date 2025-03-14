# LLMASS

**LLM Ambidextrous Shell Synchronizer**

Enables an **LLM** to remotely & securely control a jumphost using synchronous or asynchronous `GET` requests.

Version: 2025-03-03-v1

## License

This project is released by [Jared Folkins](https://x.com/jf0lkins) under the [MIT License](https://opensource.org/licenses/MIT). See the [GITHUB](https://github.com/jaredfolkins/llm-ambidextrous-shell-synchronizer) for more details.

## Overview

**LLMASS** is a simple HTTP server written in Go that executes shell commands based on incoming HTTP `GET` requests. The server maintains a directory-based session system, issuing tickets per command, which allows quick chronological viewing of command output.

## Demo

![](assets/rce.gif)

## Features

- **Secure Hash Check**: Requires >= 32-character `HASH` for request authentication.
- **Sessions**: Commands are organized into `sessions` where each command gets a ticket number with its output saved to file.
- **Manage session**: Generate a session by value and clear the session if needing to start fresh.
- **Terminal**: Retrieve all outputs for a session.
- **Ticket**: Retrieve a specific ticket from a session.
- **Documentation**: Serves a dynamically rendered markdown `README.md`.
- **Ambidextrous**: Can be configured to be asynchronous/synchronous via the environment variable `SYNC`.

## Requirements

- [Go 1.21+](https://golang.org/dl/) (earlier versions may work, but this was tested with 1.18+).
- A `.env` file containing environment variables (example found '.example.env`).
- (Optional) [Caddy](https://caddyserver.com) as a reverse proxy.

## Installation and Setup

#### Clone the Repository

```bash
git clone https://github.com/jaredfolkins/llm-ambidextrous-shell-synchronizer.git
cd llm-ambidextrous-shell-synchronizer
```

#### Create a file named `.env` in the project root:

```bash
touch .env
```

And populate it with the required environment variables.

#### Install Dependencies

 ```bash
 go mod tidy
 ```

#### Build and Run

 ```bash
 go build -o llmass
 ./llmass
 ```
By default, the server will start listening on the port specified in your `.env`.

## Configuration


LLMASS relies on several environment variables that you need to place in a `.env` file.

**Important**:

The `HASH` must be >= 32 characters long.

**Example**:
```dotenv
HASH=REPLACE_ME_WITH_THE_HASH_YOU_WERE_PROVIDED
FQDN=http://localhost:8083
PORT=8083
SESSIONS_DIR=sessions
SYNC=true
DEMO=true
```

## Parameter Map

| Endpoint   | hash     | b64cmd   | ticket   | session  | name     | clear    |
|------------|----------|----------|----------|----------|----------|----------|
| `/shell`   | Required | Required | N/A      | Required | N/A      | N/A      |
| `/history` | Required | N/A      | N/A      | Required | N/A      | N/A      |
| `/callback`| Required | N/A      | Required | Required | N/A      | N/A      |
| `/context` | Required | N/A      | N/A      | N/A      | N/A      | N/A      |
| `/session` | Required | N/A      | N/A      | N/A      | Required | Optional |
| `/`        | N/A      | N/A      | N/A      | N/A      | N/A      | N/A      |



## Shell

- **Description**: Execute a shell command.
- **Path**: [{FQDN}/shell]({FQDN}/shell)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH` from your `.env`.
  - `b64cmd`: A base64-encoded shell command (alternative to `cmd`).
  - `session`: A directory/session name

### Command Parameter Options

The `/shell` endpoint supports two methods for specifying commands:

#### Base64-encoded Command Parameter (`b64cmd`)

```
/shell?hash=YOUR_HASH&session=SESSION_NAME&b64cmd=bHMgLWxhCg==
```

- Accepts commands encoded in base64 format
- Ideal for complex commands with special characters
- Supports multi-line commands without URL encoding issues
- Helps prevent problems with shell escaping and quotation marks

**Note**: You must provide `b64cmd` parameter.

#### Examples 

**Encoding a multi-line command:**

```bash
# Original multi-line command
cat <<EOF > test.sh
#!/bin/bash
echo "Hello World"
EOF

# Base64 encoded version
# Y2F0IDw8RU9GID4gdGVzdC5zaAojIS9iaW4vYmFzaAplY2hvICJIZWxsbyBXb3JsZCIKRU9G
```

**Examples**:
# Using base64-encoded command
curl -G "{FQDN}/shell" --data-urlencode "b64cmd=bHMgLWxhaAo=" --data-urlencode "hash=REPLACE_ME_WITH_THE_HASH_YOU_WERE_PROVIDED" --data-urlencode "session=mysession"
```

## Status

- **Description**: Returns the output of a specific ticket once the command has completed.
- **Path**: [{FQDN}/callback]({FQDN}/callback)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH`.
  - `session`: The session name to fetch the ticket from.
  - `ticket`: The specific ticket number to retrieve.

**Example**:
```bash
curl -G "{FQDN}/callback?session=REPLACE_WITH_YOUR_SESSION&ticket=REPLACE_WITH_YOUR_TICKET_ID&hash=REPLACE_ME_WITH_THE_HASH_YOU_WERE_PROVIDED"
```

## History

- **Description**: Returns all command history for a session.
- **Path**: [{FQDN}/history]({FQDN}/history)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH`.
  - `session`: The session name to fetch the ticket from.

**Example**:
```bash
curl -G "{FQDN}/history?session=REPLACE_WITH_YOUR_SESSION&hash=REPLACE_ME_WITH_THE_HASH_YOU_WERE_PROVIDED"
```

## Context

- **Description**: Returns the inital context for the LLM.
- **Path**: [{FQDN}/context]({FQDN}/context)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH`.

**Example**:
```bash
curl -G "{FQDN}/context?hash=REPLACE_ME_WITH_THE_HASH_YOU_WERE_PROVIDED"
```

## Index

- **Description**: : Displays the README.md file in the root directory as HTML
- **Path**: [{FQDN}/]({FQDN}/)
- **Method**: `GET`

**Example**
```bash
curl -G "{FQDN}/"
```

## Session

- **Description**: Create or reset a session with a specific name.
- **Path**: [{FQDN}/session]({FQDN}/session)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH` from your `.env`.
  - `name`: The name to assign to the session.
  - `clear`: Optional. If set to "true", deletes the existing session before creating a new one.

The Session endpoint allows you to explicitly create a new session or clear an existing one. Sessions are used to group commands and their outputs together, maintaining context across multiple commands.

**Examples**:
```bash
# Create a new session
curl -G "{FQDN}/session" --data-urlencode "hash=YOUR_32CHAR_HASH" --data-urlencode "name=my_new_session"

# Reset an existing session (delete and recreate)
curl -G "{FQDN}/session" --data-urlencode "hash=YOUR_32CHAR_HASH" --data-urlencode "name=my_existing_session" --data-urlencode "clear=true"
```

## Session Directory Structure

After running commands, you’ll see a structure like:
```
.
├── sessions
│   └── YOUR_SESSION_NAME
│       ├── 1.ticket
│       ├── 2.ticket
│       └── ...
├── main.go
├── README.md
└── .env
```
- **sessions**: The default `SESSIONS_DIR` unless overridden in `.env`.
- **session-name**: Each session is a subdirectory.
- **1.ticket, 2.ticket**: Text files containing the command outputs (or errors).

## Important Notes
- Replace {FQDN} with actual server URL
- Replace YOUR_32CHAR_HASH with actual hash
- URL encode all commands
- Use same session name for command sequence
- Wait for each command to complete
- Ensure that `HASH` is random and never checked into source control.
- Secure your server and be responsible.
- Happy hacking!