# LLMASS

**LLM Ambidextrous Shell Synchronizer**

tldr; Enables an **LLM** to remotely & securely control a jumphost using asynchronous `GET` requests. 

## License

This project is released by [Jared Folkins](https://x.com/jf0lkins) under the [MIT License](https://opensource.org/licenses/MIT). See the [GITHUB](https://github.com/jaredfolkins/llm-ambidextrous-shell-synchronizer) for more details.

## Overview

**LLMASS** is a simple HTTP server written in Go that executes shell commands based on incoming HTTP `GET` requests. The server maintains a directory-based session system, issuing tickets per command, which allows quick chronological viewing of command output.

## Features

- **Secure Hash Check**: Requires >= 32-character `HASH` for request authentication.
- **Sessions**: Commands are organized into `sessions` where each command gets a ticket number with its output saved to file.
- **Dynamic Group Names**: Automatically generate a random session name if not specified.
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
```


## Parameter Map

| GET Parameter | Description                                        | /shell   | /history | /callback | /context   | /       |
|---------------|----------------------------------------------------|----------|----------|-----------|------------|---------|
| `hash`        | >= 32-character password for authentication.       | required | required | required  | required   | n/a     |
| `cmd`         | Url encoded cli command to execute                 | required | n/a      | n/a       | n/a        | n/a     |
| `ticket`      | Ticket number of the request                       | n/a      | n/a      | required  | n/a        | n/a     |
| `session`     | Session in order that the llm can maintain context | required | required | required  | n/a        | n/a     |

## Shell

- **Description**: Execute a shell command.
- **Path**: [{FQDN}/shell]({FQDN}/shell)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH` from your `.env`.
  - `cmd`: is a url encoded shell command to execute, e.g., `ls -lah`.
  - `session` A directory/session name

**Example**:
```bash
curl -G "{FQDN}/shell" --data-urlencode "cmd=ls -lah" --data-urlencode "hash=REPLACE_ME_WITH_THE_HASH_YOU_WERE_PROVIDED"
```

A **successful** response returns:
```
{
  "ticket":REMEMBER_THIS_ID_TO_MANAGE_SEQUENTIAL_REQUESTS_DURING_THIS_SESSION,
  "session":"REMEMBER_SESSION_TO_MAINTAIN_CONTEXT"
}
```

The **output** of the command is:

- saved in a new named `<int>.ticket`
- the file is inside `SESSIONS_DIR/<sessionname>/`

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
 
## Procedure for LLM Consumption

#### 1. Initial Command Request:

Request

```
curl -G "{FQDN}/shell" \
--data-urlencode "hash=YOUR_32CHAR_HASH" \
--data-urlencode "session=my_session" \
--data-urlencode "cmd=ls -la"
```

Response

```
{
 "type": "submission",
 "ticket": 1,
 "session": "my_session",
 "input": "ls -la",
 "callback": "{FQDN}/callback?hash=YOUR_32CHAR_HASH&session=my_session&ticket=1"
}
```

#### 2. Check Command Status:

**Request**

```
  curl -G "{FQDN}/callback" \
  --data-urlencode "hash=YOUR_32CHAR_HASH" \
  --data-urlencode "session=my_session" \
  --data-urlencode "ticket=1"
```

**Response**

IF command is still running:**

Description: Command for ticket 1 is still executing

Next: Wait a moment and try the callback URL again

**IF command is complete:**

Description: Command execution completed

Next: You can now issue your next command to /shell

```
{
"type": "result",
"ticket": 1,
"session": "my_session",
"input": "ls -la",
"output": "total 32\ndrwxr-xr-x..."
}
```

#### 3. View Session History:

``` 
   curl -G "{FQDN}/history" \
   --data-urlencode "hash=YOUR_32CHAR_HASH" \
   --data-urlencode "session=my_session"
```

#### 4. Next Command:

```
   curl -G "{FQDN}/shell" \
   --data-urlencode "hash=YOUR_32CHAR_HASH" \
   --data-urlencode "session=my_session" \
   --data-urlencode "cmd=pwd"
```
