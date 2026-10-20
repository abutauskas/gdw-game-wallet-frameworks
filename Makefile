# Convenience targets for the Game Digital Wallet (GDW) javascript framework.
# The language lives at this branch's root; SPEC.md and test-vectors/ are shared.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test clean

help:
	@echo "make test   run the javascript conformance suite"
	@echo "make clean  remove local build artifacts"

test:
	node test/run_tests.js && node test/test_units.js

clean:
	rm -rf build
