# Convenience targets for the Game Digital Wallet (GDW) gdscript framework.
# See SPEC.md for the wire format and ../test-vectors for the shared vectors.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test example clean

help:
	@echo "make test     run the gdscript conformance suite"
	@echo "make example  run the end-to-end gdscript example"
	@echo "make clean    remove build artifacts"

test:
	cd gdscript && godot --headless --path . --import && godot --headless --path . --script res://tests/run_tests.gd

example:
	@echo "see the gdscript README for the run command"

clean:
	rm -rf build
