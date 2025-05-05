from dataclasses import dataclass
from eigensdk.crypto.bls.attestation import KeyPair, gen_random_bls_keys, Signature, G1Point
from eigensdk.crypto.bn256 import utils as bn256Utils
import json
import random


@dataclass
class Attestation:
    signer: G1Point
    signature: Signature
    message: bytes

    def verify(self) -> bool:
        # Get G2 generator for verification with G1 public key
        G2 = bn256Utils.get_g2_generator()
        # Map message to a G1 point
        msg_point = bn256Utils.map_to_curve(self.message)

        # For G1 public key verification
        gt1 = bn256Utils.GT.pairing(msg_point, G2)
        gt2 = bn256Utils.GT.pairing(self.signature, bn256Utils.get_g2_generator())

        return gt1 == gt2


def aggregate_attestations(attestations):
    if not attestations:
        raise ValueError("No attestations to aggregate")

    message = attestations[0].message

    aggregated_signature = attestations[0].signature
    for att in attestations[1:]:
        if att.message != message:
            raise ValueError("All attestations must be for the same message")
        aggregated_signature = aggregated_signature + att.signature

    aggregated_pubkey = attestations[0].signer
    for att in attestations[1:]:
        aggregated_pubkey = aggregated_pubkey + att.signer

    return Attestation(signer=aggregated_pubkey, signature=aggregated_signature, message=message)


operators_data = [
    {
        "id": "0x0d84f2cfff72db8b927c27d01ae90e73bf453be3",
        "socket": "http://15.204.30.246:6001",
        "stake": "33275521608384169292",
    },
    {
        "id": "0x121298c65a62d6c8a14ee44778bbe38ebea8c869",
        "socket": "http://15.235.41.237:6001",
        "stake": "1124060129820254450",
    },
    {
        "id": "0x37d5077434723d0ec21d894a52567cbe6fb2c3d8",
        "socket": "http://141.144.201.104:6001",
        "stake": "1895336718771218298",
    },
    {
        "id": "0x390ab6a8da334f2ac5d58513b583aa47fe00a716",
        "socket": "http://116.251.192.226:13816",
        "stake": "9959487765319163",
    },
    {
        "id": "0x3eaa1c283dbf13357257e652649784a4cc08078c",
        "socket": "http://5.161.230.186:6001",
        "stake": "2974982461847618543",
    },
    {
        "id": "0x4550f589086cdb5fe39bd2e6a2782e2a65a292de",
        "socket": "http://161.97.140.52:9000",
        "stake": "0",
    },
    {
        "id": "0x747b80a1c0b0e6031b389e3b7eaf9b5f759f34ed",
        "socket": "http://172.86.109.14:6001",
        "stake": "4776064595081970865",
    },
    {
        "id": "0x906585f83fa7d29b96642aa8f7b4267ab42b7b6c",
        "socket": "http://37.27.41.237:6001",
        "stake": "1980028561960706956",
    },
    {
        "id": "0x93d89ade53b8fcca53736be1a0d11d342d71118b",
        "socket": "http://89.106.206.214:6001",
        "stake": "1005776726904316428",
    },
    {
        "id": "0xa00a522975575f70180e6ba0466896786998f00e",
        "socket": "http://[168.119.4.116:4444]",
        "stake": "1981035445664413064",
    },
    {
        "id": "0xb6460a5c1ff8fd412f11c6c19e66f1449f13332d",
        "socket": "http://88.198.2.58:1515",
        "stake": "31774844676523928611",
    },
    {
        "id": "0xc5211f55ef0e06659a92e7c3a7fd675cccb58ce6",
        "socket": "http://[ip:port]",
        "stake": "1489394766091141560",
    },
    {
        "id": "0xd216ccb2d95809957a3128824dddb136d90dfde7",
        "socket": "http://213.239.206.135:9091",
        "stake": "1036678674083155839644",
    },
    {
        "id": "0xe390f8917306d3184d0a35160909998032d79de7",
        "socket": "http://[ip:port]",
        "stake": "0",
    },
    {
        "id": "0xe3b520f525b57be060f2c7b9ca0ea98a2dc4500b",
        "socket": "http://176.9.7.122:8241",
        "stake": "1686037489182236898275",
    },
]

message = b"BLS aggregation test for operators"

operator_keypairs = {}
for operator in operators_data:
    operator_keypairs[operator["id"]] = gen_random_bls_keys()

all_operators = [op["id"] for op in operators_data]
signer_ids = random.sample(all_operators, int(0.7 * len(all_operators)))
non_signer_ids = [op_id for op_id in all_operators if op_id not in signer_ids]

print(f"Signers: {json.dumps(signer_ids, indent=2)}")
print(f"Non-signers: {json.dumps(non_signer_ids, indent=2)}")

attestations = []
for signer_id in signer_ids:
    keypair = operator_keypairs[signer_id]
    signature = keypair.sign_message(message)
    attestation = Attestation(
        signer=keypair.pub_g1,  # Using G1 public key instead of G2
        signature=signature,
        message=message,
    )
    attestations.append(attestation)
    print(f"Operator {signer_id} signed the message")

if attestations:
    aggregated_attestation = aggregate_attestations(attestations)

    print("\nAggregated Attestation:")
    print(f"Public Key: {aggregated_attestation.signer.getStr().decode('utf-8')}")
    print(f"Signature: {aggregated_attestation.signature.getStr().decode('utf-8')}")

    verified = aggregated_attestation.verify()
    print(f"\nVerification result: {verified}")

    signer_stake = sum(int(op["stake"]) for op in operators_data if op["id"] in signer_ids)
    non_signer_stake = sum(int(op["stake"]) for op in operators_data if op["id"] not in signer_ids)

    print(f"\nTotal signer stake: {signer_stake}")
    print(f"Total non-signer stake: {non_signer_stake}")
    print(
        f"Percentage of stake signed: {signer_stake / (signer_stake + non_signer_stake) * 100:.2f}%"
    )

    proof = {
        "node_id": "test_node",
        "status": "up",
        "timestamp": 1234567890,
        "signature": aggregated_attestation.signature.getStr().decode("utf-8"),
        "non_signers": non_signer_ids,
        "aggregated_public_key": aggregated_attestation.signer.getStr().decode("utf-8"),
    }

    print("\nSample proof structure:")
    print(json.dumps(proof, indent=2))
else:
    print("No attestations to aggregate")
