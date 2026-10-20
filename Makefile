# Convenience targets for the Game Digital Wallet (GDW) lua framework.
# See SPEC.md for the wire format and ../test-vectors for the shared vectors.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test example clean

help:
	@echo "make test     run the lua conformance suite"
	@echo "make example  run the end-to-end lua example"
	@echo "make clean    remove build artifacts"

test:
	cd lua && lua tests/run_tests.lua && lua tests/test_units.lua

example:
	@echo "see the lua README for the run command"

clean:
	rm -rf build
