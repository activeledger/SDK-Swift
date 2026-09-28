# Activeledger SDK for Swift - common tasks.
#
# Override the live-network URLs to match what your node prints:
#   make test-live AL_NODES=http://127.0.0.1:5510 AL_STORAGE=http://127.0.0.1:5509

AL_NODES   ?= http://127.0.0.1:5510
AL_STORAGE ?= http://127.0.0.1:5509

.PHONY: build test test-live clean

## build: compile the package
build:
	swift build

## test: unit + cross-language vector tests (no ledger needed)
test:
	swift test

## test-live: integration tests against a running network
## Start one first, e.g. `npm run test:network:serve` in an activeledger checkout.
test-live:
	AL_NODES=$(AL_NODES) AL_STORAGE=$(AL_STORAGE) swift test --filter LiveNetworkTests

## clean: remove build artifacts
clean:
	swift package clean
