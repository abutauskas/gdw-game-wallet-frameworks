# Convenience targets for the Game Digital Wallet (GDW) rust framework.
# The language lives at this branch's root; SPEC.md and test-vectors/ are shared.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test clean

help:
	@echo "make test   run the rust conformance suite"
	@echo "make clean  remove local build artifacts"

test:
	cargo test --features es256

clean:
	rm -rf build
