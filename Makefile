.PHONY: test build

test:
	.venv/bin/python -m unittest discover -s tests -v
	cd go-engine && sh ../scripts/go.sh test ./...

build:
	cd go-engine && sh ../scripts/go.sh build -buildvcs=false -o dr4c-http ./cmd/dr4c-http
