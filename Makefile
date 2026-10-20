# Convenience targets for the Game Digital Wallet (GDW) lua framework.
# The language lives at this branch's root; SPEC.md and test-vectors/ are shared.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test clean

help:
	@echo "make test   run the lua conformance suite"
	@echo "make clean  remove local build artifacts"

test:
	lua tests/run_tests.lua && lua tests/test_units.lua

clean:
	rm -rf build
