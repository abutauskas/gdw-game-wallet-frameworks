# Convenience targets for the Game Digital Wallet (GDW) python framework.
# The language lives at this branch's root; SPEC.md and test-vectors/ are shared.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test clean

help:
	@echo "make test   run the python conformance suite"
	@echo "make clean  remove local build artifacts"

test:
	python3 tests/run_tests.py && python3 tests/test_units.py

clean:
	rm -rf build
