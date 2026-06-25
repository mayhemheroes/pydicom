#!/usr/bin/env python3
"""Oracle driver for mayhem/test.sh — read a DICOM file and print a fixed set of
``ELEMENT=value`` lines (a known-answer dump of CT_small.dcm).

This exercises the SAME read path the fuzzer drives (pydicom.dcmread -> element decode)
and prints decoded element values, so a neutered/no-op program produces no/garbled output
and the test.sh assertions fail. Invoked via the /mayhem/run-cli ELF launcher (a non-system
executable, so the verify-repo sabotage neuter applies to it).
"""
import sys

import pydicom

FIELDS = [
    "PatientName",
    "PatientID",
    "Modality",
    "Rows",
    "Columns",
    "StudyDate",
    "Manufacturer",
    "SOPClassUID",
]


def main():
    ds = pydicom.dcmread(sys.argv[1])
    for field in FIELDS:
        try:
            print(f"{field}={getattr(ds, field)}")
        except Exception:
            print(f"{field}=<missing>")
    print(f"TransferSyntaxUID={ds.file_meta.TransferSyntaxUID}")


if __name__ == "__main__":
    main()
