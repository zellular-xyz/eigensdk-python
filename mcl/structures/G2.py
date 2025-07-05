import types
import ctypes

from .. import utils
from .. import builder
from .Fp2 import Fp2
from .Fr import Fr


class G2(ctypes.Structure):
    _fields_ = [
        ("x", Fp2),
        ("y", Fp2),
        ("z", Fp2),
    ]


G2.__add__ = builder.buildThreeOp(G2, "add")
G2.__eq__ = builder.buildIsEqual(G2)
G2.__mul__ = builder.buildMul(G2, Fr)
G2.__neg__ = builder.buildTwoOp(G2, "neg")
G2.__sub__ = builder.buildThreeOp(G2, "sub")
G2.normalize = builder.buildNormalize(G2)
G2.deserialize = builder.buildDeserialize(G2)
G2.getStr = builder.buildGetStr(G2)
G2.hashAndMapTo = builder.buildHashAndMapTo(G2)
G2.isZero = builder.buildIsZero(G2)
G2.serialize = builder.buildSerialize(G2)
G2.setStr = builder.buildSetStr(G2)
G2.getX = builder.buildGetSubArray(G2, 0, Fp2)
G2.getY = builder.buildGetSubArray(G2, 1, Fp2)
G2.getZ = builder.buildGetSubArray(G2, 2, Fp2)
G2.clear = builder.buildClear(G2)
