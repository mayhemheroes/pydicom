#!/usr/bin/env python3
import struct

import atheris
import io
import logging
import sys
import pydicom.errors
import warnings

with atheris.instrument_imports():
    from pydicom import dcmread

logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")


@atheris.instrument_func
def TestOneInput(data):
    try:
        with io.BytesIO(data) as dcm_file:
            dcmread(dcm_file, force=True)
    except (pydicom.errors.InvalidDicomError, pydicom.errors.BytesLengthException) as e:
        return -1
    except struct.error:
        return -1
    except NotImplementedError:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
