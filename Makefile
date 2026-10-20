# Convenience targets for the Game Digital Wallet (GDW) python framework.
# See SPEC.md for the wire format and ../test-vectors for the shared vectors.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test example clean

help:
	@echo "make test     run the python conformance suite"
	@echo "make example  run the end-to-end python example"
	@echo "make clean    remove build artifacts"

test:
	cd python && python3 tests/run_tests.py && python3 tests/test_units.py

example:
	@echo "see the python README for the run command"

clean:
	rm -rf build
