import ctypes

from .. import builder
from .. import consts


class Fr(ctypes.Structure):
    _fields_ = [("v", ctypes.c_ulonglong * consts.FR_SIZE)]


Fr.__add__ = builder.buildThreeOp(Fr, "add")
Fr.__eq__ = builder.buildIsEqual(Fr)
Fr.__mul__ = builder.buildThreeOp(Fr, "mul")
Fr.__neg__ = builder.buildTwoOp(Fr, "neg")
Fr.__sub__ = builder.buildThreeOp(Fr, "sub")
Fr.__truediv__ = builder.buildThreeOp(Fr, "div")
Fr.getStr = builder.buildGetStr(Fr)
Fr.isOne = builder.buildIsOne(Fr)
Fr.isZero = builder.buildIsZero(Fr)
Fr.serialize = builder.buildSerialize(Fr)
Fr.setByCSPRNG = builder.buildSetByCSPRNG(Fr)
Fr.setInt = builder.buildSetInt(Fr)
Fr.setStr = builder.buildSetStr(Fr)
Fr.setHashOf = builder.buildSetHashOf(Fr)
Fr.clear = builder.buildClear(Fr)
