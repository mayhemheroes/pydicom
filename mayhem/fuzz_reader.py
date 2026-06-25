#!/usr/bin/env python3
"""Atheris fuzz harness for pydicom's DICOM reader (pydicom.dcmread).

Feeds the fuzzer-provided bytes to ``pydicom.dcmread`` via an in-memory stream and
swallows the parse errors a malformed DICOM stream is *expected* to raise, so only an
unexpected failure (an uncaught exception / crash inside pydicom) is reported.

Atheris is a libFuzzer engine: run with libFuzzer flags it iterates; run with a single
file argument it replays that input once (standalone reproducer). The ELF ``launcher``
(see launcher.c) exec's ``python3`` on this file, forwarding every argument unchanged.
"""
import io
import logging
import struct
import sys
import warnings

import atheris

# Instrument the whole pydicom package so Atheris gets edge coverage of the reader.
with atheris.instrument_imports():
    import pydicom
    import pydicom.errors

# DICOM parsing is noisy on garbage input — silence it so the fuzzer runs fast.
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")


@atheris.instrument_func
def TestOneInput(data):
    try:
        with io.BytesIO(data) as dcm_file:
            pydicom.dcmread(dcm_file)
    except (
        pydicom.errors.InvalidDicomError,
        pydicom.errors.BytesLengthException,
        struct.error,
        NotImplementedError,
        OSError,
        AttributeError,
    ):
        # Expected ways a malformed DICOM stream is rejected — not defects.
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
