# Convenience targets for the Game Digital Wallet (GDW) rust framework.
# See SPEC.md for the wire format and ../test-vectors for the shared vectors.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test example clean

help:
	@echo "make test     run the rust conformance suite"
	@echo "make example  run the end-to-end rust example"
	@echo "make clean    remove build artifacts"

test:
	cd rust && cargo test --features es256

example:
	@echo "see the rust README for the run command"

clean:
	rm -rf build
