import types
import ctypes

from .. import utils
from .. import builder
from .G1 import G1
from .G2 import G2
from .Fp import Fp


class GT(ctypes.Structure):
    _fields_ = [
        ("d", (Fp * 12)),
    ]


GT.__eq__ = builder.buildIsEqual(GT)
GT.__invert__ = builder.buildTwoOp(GT, "inv")
GT.pairing = builder.buildPairing(GT, G1, G2)
GT.isEqual = builder.buildIsEqual(GT)
GT.getStr = builder.buildGetStr(GT)
GT.serialize = builder.buildSerialize(GT)
GT.clear = builder.buildClear(GT)
