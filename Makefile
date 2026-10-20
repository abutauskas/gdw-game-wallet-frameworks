# Convenience targets for the Game Digital Wallet (GDW) csharp framework.
# The language lives at this branch's root; SPEC.md and test-vectors/ are shared.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test clean

help:
	@echo "make test   run the csharp conformance suite"
	@echo "make clean  remove local build artifacts"

test:
	dotnet run -c Release --project Tests/EudiGameWallet.Tests -- test-vectors/vectors.json

clean:
	rm -rf build
