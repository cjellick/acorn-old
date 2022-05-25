build:
	CGO_ENABLED=0 go build -o bin/acorn -ldflags "-s -w" .

generate:
	go generate

image:
	docker build .

validate:
	golangci-lint --timeout 5m run

validate-ci:
	go generate
	go mod tidy
	if [ -n "$$(git status --porcelain --untracked-files=no)" ]; then \
		git status --porcelain --untracked-files=no; \
		echo "Encountered dirty repo!"; \
		exit 1 \
	;fi

test:
	go test ./...

goreleaser:
	goreleaser build --snapshot --single-target --rm-dist

setup-ci-env:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.46.2

# This will initialize the node_modules needed to run the docs dev server. Run this before running serve-docs
init-docs:
	docker run -it --rm --workdir=/docs -v $${PWD}/docs:/docs node:18-buster yarn install

# Launch development server for the docs site
serve-docs:
	docker run -it --rm --workdir=/docs -p 3000:3000 -v $${PWD}/docs:/docs node:18-buster yarn start --host=0.0.0.0

gen-cli-docs:
	go run tools/gendocs/main.go
