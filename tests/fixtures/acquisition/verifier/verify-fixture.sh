#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Fixture verifier for hermetic acquisition tests.
# Never executed in tests: bounded_stream is stubbed per
# tests/test_source_authority.py:415-448, and GH_EXECUTABLE_SHA256 is
# monkeypatched to this file's digest. If run directly it emits the
# canned verified.json shape for manual inspection only.
echo '[{"verificationResult": {"fixture": true}}]'
