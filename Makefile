.PHONY: build run docker-build docker-run clean test help

# Variables
APP_NAME=llmass
DOCKER_IMAGE=llmass

# Go commands
build:
	go build -o ${APP_NAME}

run:
	air

test:
	go test -v ./...

clean:
	rm -rf tmp/
	rm -f ${APP_NAME}
	rm -f air.log

# Docker commands
docker-build:
	docker build -t ${DOCKER_IMAGE} .

docker-run:
	docker run -p 8083:8083 --env-file .env \
		--pid=host \
		--privileged \
		-v /usr/local/bin:/usr/local/bin \
		-v /usr/bin:/usr/bin \
		-v /bin:/bin \
		${DOCKER_IMAGE}

docker-clean:
	docker rmi ${DOCKER_IMAGE}

# Install dependencies
deps:
	go mod tidy
	go install github.com/cosmtrek/air@latest

help:
	@echo "Available commands:"
	@echo "  build         - Build the Go application"
	@echo "  run          - Run the application with Air for live reload"
	@echo "  test         - Run tests"
	@echo "  clean        - Remove build artifacts"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  docker-clean - Remove Docker image"
	@echo "  deps         - Install dependencies"