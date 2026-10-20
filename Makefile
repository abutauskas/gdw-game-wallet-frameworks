# Convenience targets for the Game Digital Wallet (GDW) javascript framework.
# See SPEC.md for the wire format and ../test-vectors for the shared vectors.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test example clean

help:
	@echo "make test     run the javascript conformance suite"
	@echo "make example  run the end-to-end javascript example"
	@echo "make clean    remove build artifacts"

test:
	cd javascript && node test/run_tests.js && node test/test_units.js

example:
	@echo "see the javascript README for the run command"

clean:
	rm -rf build
