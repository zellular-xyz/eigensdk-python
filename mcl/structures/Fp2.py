import ctypes

from .Fp import Fp
from ..hook import mclbn384_256
from .. import builder


class Fp2(ctypes.Structure):
    _fields_ = [("d", Fp * 2)]


Fp2.get_a = builder.buildGetSubArray(Fp2, 1, Fp)
Fp2.get_b = builder.buildGetSubArray(Fp2, 0, Fp)
Fp2.clear = builder.buildClear(Fp2)
