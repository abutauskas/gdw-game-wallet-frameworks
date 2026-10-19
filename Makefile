# Convenience targets for the Game Digital Wallet frameworks.
# Each target is self-contained; run them from frameworks/.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help vectors test test-cpp test-csharp test-gdscript test-rust examples clean

GODOT ?= godot
PYTHON ?= python3
CARGO ?= cargo

help:
	@echo "make vectors      regenerate test-vectors/vectors.json"
	@echo "make test         run all four conformance suites"
	@echo "make test-cpp     build and run the C++ tests (ctest)"
	@echo "make test-csharp  run the C# tests (dotnet)"
	@echo "make test-gdscript run the GDScript tests (Godot, headless)"
	@echo "make test-rust    run the Rust tests (cargo, with ES256)"
	@echo "make examples     build/run the four end-to-end examples"
	@echo "make clean        remove build artifacts"
	@echo ""
	@echo "Override the Godot binary with: make test-gdscript GODOT=/path/to/godot"

vectors:
	cd test-vectors && $(PYTHON) generate_vectors.py

test: test-cpp test-csharp test-gdscript test-rust

test-cpp:
	cd cpp && cmake -S . -B build >/dev/null && cmake --build build >/dev/null
	cd cpp/build && ctest --output-on-failure

test-csharp:
	cd csharp && dotnet run -c Release --project Tests/EudiGameWallet.Tests -- ../test-vectors/vectors.json

test-gdscript:
	cd gdscript && $(GODOT) --headless --path . --import >/dev/null 2>&1 || true
	cd gdscript && $(GODOT) --headless --path . --script res://tests/run_tests.gd

test-rust:
	cd rust && $(CARGO) test --features es256

examples:
	cd cpp && cmake -S . -B build >/dev/null && cmake --build build >/dev/null && ./build/basic_flow
	cd csharp && dotnet run -c Release --project Examples/BasicFlow
	cd gdscript && $(GODOT) --headless --path . --script res://examples/basic_flow.gd
	cd rust && $(CARGO) run --example basic_flow

clean:
	rm -rf cpp/build
	rm -rf csharp/**/bin csharp/**/obj
	rm -rf gdscript/.godot
	rm -rf rust/target
