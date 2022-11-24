#!/usr/bin/env python3
import struct

import atheris
import io
import logging
import sys
import warnings

include_imports = [
    'pydicom.overlays,'
    'pydicom.data',
    'pydicom.overlays.numpy_handler',
    'pydicom.data',
    'pydicom.data.data_manager',
    'pydicom.data.download'
]
with atheris.instrument_imports(include=['pydicom.ma.extras"']):
    import pydicom

import pydicom.errors

logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")


@atheris.instrument_func
def TestOneInput(data):
    try:
        with io.BytesIO(data) as dcm_file:
            pydicom.dcmread(dcm_file)
    except (pydicom.errors.InvalidDicomError, pydicom.errors.BytesLengthException, OSError, AttributeError) as e:
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
