# Convenience targets for the Game Digital Wallet (GDW) cpp framework.
# The language lives at this branch's root; SPEC.md and test-vectors/ are shared.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test clean

help:
	@echo "make test   run the cpp conformance suite"
	@echo "make clean  remove local build artifacts"

test:
	cmake -S . -B build && cmake --build build && (cd build && ctest --output-on-failure)

clean:
	rm -rf build
