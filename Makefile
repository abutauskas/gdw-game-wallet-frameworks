# Convenience targets for the Game Digital Wallet (GDW) csharp framework.
# See SPEC.md for the wire format and ../test-vectors for the shared vectors.
#
# SPDX-License-Identifier: CC-BY-4.0

.PHONY: help test example clean

help:
	@echo "make test     run the csharp conformance suite"
	@echo "make example  run the end-to-end csharp example"
	@echo "make clean    remove build artifacts"

test:
	cd csharp && dotnet run -c Release --project Tests/EudiGameWallet.Tests -- ../test-vectors/vectors.json

example:
	@echo "see the csharp README for the run command"

clean:
	rm -rf build
