import ctypes

from .. import builder
from .. import consts


class Fp(ctypes.Structure):
    _fields_ = [("v", ctypes.c_ulonglong * consts.FP_SIZE)]


Fp.__add__ = builder.buildThreeOp(Fp, "add")
Fp.__eq__ = builder.buildIsEqual(Fp)
Fp.__invert__ = builder.buildTwoOp(Fp, "inv")
Fp.__mul__ = builder.buildThreeOp(Fp, "mul")
Fp.__neg__ = builder.buildTwoOp(Fp, "neg")
Fp.__sub__ = builder.buildThreeOp(Fp, "sub")
Fp.__truediv__ = builder.buildThreeOp(Fp, "div")
Fp.deserialize = builder.buildDeserialize(Fp)
Fp.getStr = builder.buildGetStr(Fp)
Fp.isOne = builder.buildIsOne(Fp)
Fp.isZero = builder.buildIsZero(Fp)
Fp.serialize = builder.buildSerialize(Fp)
Fp.setByCSPRNG = builder.buildSetByCSPRNG(Fp)
Fp.setInt = builder.buildSetInt(Fp)
Fp.setStr = builder.buildSetStr(Fp)
Fp.clear = builder.buildClear(Fp)
