import ctypes

from . import hook
from . import utils

BUFFER_SIZE = 2048


def buildClear(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_clear",
        None,
        [ctypes.POINTER(cls)],
    )

    def clear(self):
        return wrapper(self)

    return clear


def buildSetStr(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_setStr",
        None,
        [ctypes.POINTER(cls), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int64],
    )

    def setStr(self, value, mode=10):
        return wrapper(self, value, len(value), mode)

    return setStr


def buildSetInt(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_setInt",
        None,
        [ctypes.POINTER(cls), ctypes.c_int64],
    )

    def setInt(self, value):
        return wrapper(self, value)

    return setInt


def buildSetByCSPRNG(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_setByCSPRNG",
        None,
        [ctypes.POINTER(cls)],
    )

    def setByCSPRNG(self):
        return wrapper(self)

    return setByCSPRNG


def buildNormalize(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_normalize",
        None,
        [ctypes.POINTER(cls), ctypes.POINTER(cls)],
    )

    def normalize(self):
        result = cls()
        wrapper(result, self)
        return result

    return normalize


def buildGetSubArray(cls, idx, sub_cls):
    def getSubArray(self):
        addr = ctypes.addressof(self)
        result = sub_cls.from_address(addr + (ctypes.sizeof(sub_cls) * idx))
        return result

    return getSubArray;


def buildGetStr(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_getStr",
        None,
        [
            (ctypes.c_char * (BUFFER_SIZE + 1)),
            ctypes.c_size_t,
            ctypes.POINTER(cls),
            ctypes.c_uint64,
        ],
    )

    def getStr(self, mode=10):
        buffer = ctypes.create_string_buffer(b"\0" * BUFFER_SIZE)
        wrapper(buffer, BUFFER_SIZE, self, mode)
        return buffer.value

    return getStr


def buildIsEqual(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_isEqual",
        ctypes.c_int64,
        [ctypes.POINTER(cls), ctypes.POINTER(cls)],
    )

    def isEqual(self, other):
        return wrapper(self, other) == 1

    return isEqual


def buildIsOne(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256, f"mclBn{cls.__name__}_isOne", None, [ctypes.POINTER(cls)],
    )

    def isOne(self, other):
        return wrapper(self) == 1

    return isOne


def buildIsZero(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_isZero",
        ctypes.c_int64,
        [ctypes.POINTER(cls)],
    )

    def isZero(self, other):
        return wrapper(self) == 1

    return isZero


def buildThreeOp(cls, op_name):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_{op_name}",
        None,
        [ctypes.POINTER(cls), ctypes.POINTER(cls), ctypes.POINTER(cls)],
    )

    def op(self, other):
        result = cls()
        wrapper(result, self, other)
        return result

    op.__name__ = op_name
    return op


def buildTwoOp(cls, op_name):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_{op_name}",
        None,
        [ctypes.POINTER(cls), ctypes.POINTER(cls)],
    )

    def op(self):
        result = cls()
        wrapper(result, self)
        return result

    op.__name__ = op_name
    return op


def buildMul(cls, right_op):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_mul",
        None,
        [ctypes.POINTER(cls), ctypes.POINTER(cls), ctypes.POINTER(right_op)],
    )

    def mul(self, right):
        result = cls()
        wrapper(result, self, right)
        return result

    return mul


def buildSerialize(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_serialize",
        ctypes.c_size_t,
        [
            (ctypes.c_char * (BUFFER_SIZE + 1)),
            ctypes.c_size_t,
            ctypes.POINTER(cls),
            ctypes.c_uint64,
        ],
    )

    def serialize(self, mode=10):
        buffer = ctypes.create_string_buffer(b"\0" * BUFFER_SIZE)
        len = wrapper(buffer, BUFFER_SIZE, self, mode)
        return bytes(bytearray(buffer[:len]))

    return serialize


def buildDeserialize(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_deserialize",
        None,
        [
            ctypes.POINTER(cls),
            (ctypes.c_char * (BUFFER_SIZE + 1)),
            ctypes.c_size_t,
        ],
    )

    def deserialize(self, value):
        if len(value) > BUFFER_SIZE:
            raise RuntimeError(f"deserialize error: value is more than a buffer size.")
        buffer = ctypes.create_string_buffer(b"\0" * BUFFER_SIZE)
        ctypes.memmove(buffer, value, len(value))
        wrapper(self, buffer, BUFFER_SIZE)

    return deserialize


def buildSetHashOf(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_setHashOf",
        None,
        [ctypes.POINTER(cls), ctypes.c_char_p, ctypes.c_size_t],
    )

    def setHashOf(self, value):
        return wrapper(self, ctypes.c_char_p(value), len(value))

    return setHashOf


def buildHashAndMapTo(cls):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn{cls.__name__}_hashAndMapTo",
        None,
        [ctypes.POINTER(cls), ctypes.c_char_p, ctypes.c_size_t],
    )

    @staticmethod
    def hashAndMapTo(value):
        result = cls()
        wrapper(result, ctypes.c_char_p(value), len(value))
        return result

    return hashAndMapTo


def buildPairing(cls, left_group, right_group):
    wrapper = utils.wrap_function(
        hook.mclbn384_256,
        f"mclBn_pairing",
        None,
        [ctypes.POINTER(cls), ctypes.POINTER(left_group), ctypes.POINTER(right_group),],
    )

    @staticmethod
    def pairing(g1, g2):
        result = cls()
        wrapper(result, g1, g2)
        # print(f"paring: g1: {g1.serialize().hex()}")
        # print(f"paring: g2: {g2.getStr()}")
        # print(f"paring: gt: {result.getStr()}")
        # print(f"paring: done ==============================")
        return result

    return pairing
