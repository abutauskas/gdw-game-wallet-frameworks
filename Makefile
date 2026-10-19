# Convenience targets for the Game Digital Wallet frameworks.
# Each target is self-contained; run them from frameworks/.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help vectors test test-cpp test-csharp test-gdscript examples clean

GODOT ?= godot
PYTHON ?= python3

help:
	@echo "make vectors      regenerate test-vectors/vectors.json"
	@echo "make test         run all three conformance suites"
	@echo "make test-cpp     build and run the C++ tests (ctest)"
	@echo "make test-csharp  run the C# tests (dotnet)"
	@echo "make test-gdscript run the GDScript tests (Godot, headless)"
	@echo "make examples     build/run the three end-to-end examples"
	@echo "make clean        remove build artifacts"
	@echo ""
	@echo "Override the Godot binary with: make test-gdscript GODOT=/path/to/godot"

vectors:
	cd test-vectors && $(PYTHON) generate_vectors.py

test: test-cpp test-csharp test-gdscript

test-cpp:
	cd cpp && cmake -S . -B build >/dev/null && cmake --build build >/dev/null
	cd cpp/build && ctest --output-on-failure

test-csharp:
	cd csharp && dotnet run -c Release --project Tests/EudiGameWallet.Tests -- ../test-vectors/vectors.json

test-gdscript:
	cd gdscript && $(GODOT) --headless --path . --import >/dev/null 2>&1 || true
	cd gdscript && $(GODOT) --headless --path . --script res://tests/run_tests.gd

examples:
	cd cpp && cmake -S . -B build >/dev/null && cmake --build build >/dev/null && ./build/basic_flow
	cd csharp && dotnet run -c Release --project Examples/BasicFlow
	cd gdscript && $(GODOT) --headless --path . --script res://examples/basic_flow.gd

clean:
	rm -rf cpp/build
	rm -rf csharp/**/bin csharp/**/obj
	rm -rf gdscript/.godot
