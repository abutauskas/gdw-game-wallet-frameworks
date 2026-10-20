# Convenience targets for the Game Digital Wallet (GDW) cpp framework.
# See SPEC.md for the wire format and ../test-vectors for the shared vectors.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test example clean

help:
	@echo "make test     run the cpp conformance suite"
	@echo "make example  run the end-to-end cpp example"
	@echo "make clean    remove build artifacts"

test:
	cd cpp && cmake -S . -B build && cmake --build build && (cd build && ctest --output-on-failure)

example:
	@echo "see the cpp README for the run command"

clean:
	rm -rf build
