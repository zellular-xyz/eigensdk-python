from typing import Tuple
from eigensdk.crypto.bls import G1Point, G2Point 
from math import big  


class BN254G1Point:
    def __init__(self, x: int, y: int):
        self.X = x
        self.Y = y


class BN254G2Point:
    def __init__(self, x: Tuple[int, int], y: Tuple[int, int]):
        self.X = x
        self.Y = y


def convert_bn254_geth_to_gnark(input_point: BN254G1Point) -> G1Point:
    return G1Point(input_point.X, input_point.Y).to_g1_affine()


def convert_to_bn254_g1_point(input_point: G1Point) -> BN254G1Point:
    return BN254G1Point(
        x=input_point.X.to_big_int(),  # Assuming method exists
        y=input_point.Y.to_big_int()
    )


def convert_to_bn254_g2_point(input_point: G2Point) -> BN254G2Point:
    return BN254G2Point(
        x=(input_point.X.A1.to_big_int(), input_point.X.A0.to_big_int()),
        y=(input_point.Y.A1.to_big_int(), input_point.Y.A0.to_big_int())
    )