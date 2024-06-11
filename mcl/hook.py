import contextlib
import ctypes
import os
import pathlib
import platform
import sys
import textwrap

from . import consts

DIR_FOR_LINKER = os.environ.get("MCL_PATH", "/usr/local")


@contextlib.contextmanager
def change_cwd(path):
    current_cwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(current_cwd)


def get_dll(path, *args):
    try:
        return ctypes.CDLL(path, *args)
    except OSError:
        print(
            textwrap.dedent(
                f"""
        Failed to import mcl shared library from:

        {DIR_FOR_LINKER}

        Please set your mcl installation dir path to MCL_PATH and run again

        export MCL_PATH=<path to mcl library>

        """
            )
        )
        sys.exit(1)


with change_cwd(DIR_FOR_LINKER):
    system = platform.system()
    if system == "Darwin":
        mclbn384_256 = get_dll("lib/libmclbn384_256.dylib")
    elif system == "Linux":
        get_dll('lib/libmcl.so', ctypes.RTLD_GLOBAL)
        mclbn384_256 = get_dll("lib/libmclbn384_256.so")
    else:
        raise RuntimeError(f"Unsupported OS {system}")


# ret = mclbn384_256.mclBn_init(consts.BN384_256, consts.MCLBN_COMPILED_TIME_VAR)
ret = mclbn384_256.mclBn_init(consts.BN_SNARK1, consts.MCLBN_COMPILED_TIME_VAR)

if ret:
    raise RuntimeError(f"mclbn384_256 ret {ret}")
