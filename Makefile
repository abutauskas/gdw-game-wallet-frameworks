# Convenience targets for the Game Digital Wallet (GDW) gdscript framework.
# The language lives at this branch's root; SPEC.md and test-vectors/ are shared.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test clean

help:
	@echo "make test   run the gdscript conformance suite"
	@echo "make clean  remove local build artifacts"

test:
	godot --headless --path . --import && godot --headless --path . --script res://tests/run_tests.gd

clean:
	rm -rf build
