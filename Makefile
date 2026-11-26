BINARY := syncnow-relay
VERSION := 0.4.0
LDFLAGS := -s -w

.PHONY: test build build-all docker cf-typecheck cf-deploy clean

test:
	go test -v ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

build-all:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 .

docker:
	docker build -t syncnow-relay:$(VERSION) -t syncnow-relay:latest .

cf-typecheck:
	npm run typecheck

cf-deploy:
	npx wrangler deploy

clean:
	rm -rf dist $(BINARY)
