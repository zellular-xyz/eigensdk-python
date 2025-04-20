import ecdsa
import logging
import os
from eth_typing import Address
from typing import List, Optional, Dict, Any
from web3 import Web3
from web3.contract.contract import Contract
from web3.types import TxParams
from eth_account.messages import encode_defunct
from eigensdk.chainio.utils import (
    BN254G1Point,
    convert_to_bn254_g2_point,
    convert_to_bn254_g1_point,
    convert_bn254_geth_to_gnark,
)
from eigensdk.crypto.bls.attestation import BLSKeyPair
from ..elcontracts.reader import ELReader


class AvsRegistryWriter:
    def __init__(
        self,
        registry_coordinator: Contract,
        operator_state_retriever: Contract,
        service_manager: Contract,
        service_manager_addr: Address,
        stake_registry: Contract,
        bls_apk_registry: Contract,
        el_reader: ELReader,
        logger: logging.Logger,
        eth_client: Web3,
        tx_mgr: Any = None,
        service_manager_abi: Optional[List[Dict[str, Any]]] = None,
    ):

        self.registry_coordinator: Contract = registry_coordinator
        self.operator_state_retriever: Contract = operator_state_retriever
        self.service_manager: Contract = service_manager
        self.service_manager_addr: Address = service_manager_addr
        self.stake_registry: Contract = stake_registry
        self.bls_apk_registry: Contract = bls_apk_registry
        self.el_reader: ELReader = el_reader
        self.logger: logging.Logger = logger
        self.eth_client: Web3 = eth_client
        self.web3: Web3 = eth_client  # Create alias for compatibility
        self.tx_mgr: Any = tx_mgr
        self.service_manager_abi: Optional[List[Dict[str, Any]]] = service_manager_abi

        if registry_coordinator is None:
            raise ValueError("RegistryCoordinator contract not provided")

        if bls_apk_registry is None:
            raise ValueError("BLSApkRegistry contract not provided")

        if operator_state_retriever is None:
            raise ValueError("OperatorStateRetriever contract not provided")

        if service_manager is None:
            raise ValueError("ServiceManager contract not provided")

        if stake_registry is None:
            raise ValueError("StakeRegistry contract not provided")

    def send(self, tx_func, *args, wait_for_receipt: bool = True):
        tx = tx_func(*args).build_transaction()
        return self.tx_mgr.send(tx, wait_for_receipt)

    def register_operator(
        self,
        operator_ecdsa_private_key: ecdsa.SigningKey,
        bls_key_pair: BLSKeyPair,
        quorum_numbers: List[int],
        socket: str,
        wait_for_receipt: bool,
    ) -> Optional[Dict]:
        operator_addr = self.web3.eth.account.from_key(
            operator_ecdsa_private_key
        ).address
        g1_hashed_msg_to_sign = self.registry_coordinator.functions.pubkeyRegistrationMessageHash(
            operator_addr
        ).call()
        g1_hashed_msg_as_point = BN254G1Point(g1_hashed_msg_to_sign[0], g1_hashed_msg_to_sign[1])
        signed_msg = bls_key_pair.sign_hashed_to_curve_message(
            convert_bn254_geth_to_gnark(g1_hashed_msg_as_point)
        )

        g1_pubkey_bn254, g2_pubkey_bn254 = convert_to_bn254_g1_point(
            bls_key_pair.get_pub_g1()
        ), convert_to_bn254_g2_point(bls_key_pair.get_pub_g2())
        
        # Convert from dictionary to properly structured tuple for contract

        pubkey_reg_params = (
            (int(signed_msg.getX().getStr()), int(signed_msg.getY().getStr())),  
            (int(g1_pubkey_bn254.X), int(g1_pubkey_bn254.Y)),  # pubkeyG1 as tuple
            ((int(g2_pubkey_bn254.X[0]),int(g2_pubkey_bn254.X[1])), (int(g2_pubkey_bn254.Y[0]),int(g2_pubkey_bn254.Y[1]))),  # pubkeyG2 as tuple
        )

        signature_salt, sig_valid_for_seconds = (
            '0x' + os.urandom(32).hex(),
            60 * 60,
        )


        # Get the latest block instead of using block_number to avoid BlockNotFound errors
        current_timestamp = self.web3.eth.get_block('latest')["timestamp"]
        signature_expiry = current_timestamp + sig_valid_for_seconds
        
        msg_to_sign = self.el_reader.calculate_operator_avs_registration_digest_hash(
            operator_addr, self.service_manager_addr, signature_salt, signature_expiry
        )
        operator_signature_bytes = self.web3.eth.account.sign_message(
            encode_defunct(msg_to_sign), operator_ecdsa_private_key
        ).signature
        operator_signature_bytes = operator_signature_bytes[:-1] + bytes(
            [operator_signature_bytes[-1] + 27]
        )
        
        # Convert from dictionary to properly structured tuple for contract
        operator_signature_with_salt_and_expiry = (
            operator_signature_bytes,  # signature as bytes
            signature_salt,  # salt as bytes32
            signature_expiry,  # expiry as uint256
        )
        
        return self.send(
            self.registry_coordinator.functions.registerOperator,
            bytes(quorum_numbers),
            socket,
            pubkey_reg_params,
            operator_signature_with_salt_and_expiry,
            wait_for_receipt=wait_for_receipt,
        )

    def update_stakes_of_entire_operator_set_for_quorums(
        self,
        operators_per_quorum: List[List[str]],
        quorum_numbers: List[int],
        wait_for_receipt: bool,
    ) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.updateOperatorsForQuorum,
            operators_per_quorum,
            quorum_numbers,
            wait_for_receipt=wait_for_receipt,
        )

    def register_operator_with_churn(
        self,
        operator_ecdsa_private_key: ecdsa.SigningKey,
        churn_approval_ecdsa_private_key: ecdsa.SigningKey,
        bls_key_pair: BLSKeyPair,
        quorum_numbers: List[int],
        quorum_numbers_to_kick: List[int],
        operators_to_kick: List[str],
        socket: str,
        wait_for_receipt: bool,
    ) -> Optional[Dict]:
        operator_addr = self.web3.eth.account.from_key(
            operator_ecdsa_private_key.to_string()
        ).address

        g1_hashed_msg_to_sign = self.registry_coordinator.functions.pubkeyRegistrationMessageHash(
            operator_addr
        ).call()
        g1_hashed_msg_as_point = BN254G1Point(g1_hashed_msg_to_sign[0], g1_hashed_msg_to_sign[1])
        signed_msg = bls_key_pair.sign_hashed_to_curve_message(
            convert_bn254_geth_to_gnark(g1_hashed_msg_as_point)
        ).g1_point
        g1_pubkey_bn254, g2_pubkey_bn254 = convert_to_bn254_g1_point(
            bls_key_pair.get_pub_g1()
        ), convert_to_bn254_g2_point(bls_key_pair.get_pub_g2())

        pubkey_reg_params = {
            "pubkeyRegistrationSignature": signed_msg,
            "pubkeyG1": g1_pubkey_bn254,
            "pubkeyG2": g2_pubkey_bn254,
        }
        signature_salt, cur_block_num, sig_valid_for_seconds = (
            os.urandom(32),
            self.web3.eth.block_number,
            60 * 60,
        )  # 1 hour
        signature_expiry = (
            self.web3.eth.get_block(cur_block_num)["timestamp"] + sig_valid_for_seconds
        )

        msg_to_sign = self.el_reader.calculate_operator_avs_registration_digest_hash(
            operator_addr, self.service_manager_addr, signature_salt, signature_expiry
        )
        operator_signature_bytes = self.web3.eth.account.sign_message(
            msg_to_sign, operator_ecdsa_private_key
        ).signature
        operator_signature_bytes = operator_signature_bytes[:-1] + bytes(
            [operator_signature_bytes[-1] + 27]
        )

        operator_signature_with_salt_and_expiry = {
            "signature": operator_signature_bytes,
            "salt": signature_salt,
            "expiry": signature_expiry,
        }
        operator_kick_params = [
            {"operator": op, "quorumNumber": quorum_numbers_to_kick[i]}
            for i, op in enumerate(operators_to_kick)
        ]

        churn_signature_salt = os.urandom(32)
        operator_id_bytes = bytes.fromhex(bls_key_pair.get_pub_g1().get_operator_id()[2:])
        churn_msg_to_sign = (
            self.registry_coordinator.functions.calculateOperatorChurnApprovalDigestHash(
                operator_addr,
                operator_id_bytes,
                operator_kick_params,
                churn_signature_salt,
                signature_expiry,
            ).call()
        )

        churn_approval_signature_bytes = self.web3.eth.account.sign_message(
            churn_msg_to_sign, churn_approval_ecdsa_private_key
        ).signature
        churn_approval_signature_bytes = churn_approval_signature_bytes[:-1] + bytes(
            [churn_approval_signature_bytes[-1] + 27]
        )

        churn_approver_signature_with_salt_and_expiry = {
            "signature": churn_approval_signature_bytes,
            "salt": churn_signature_salt,
            "expiry": signature_expiry,
        }

        # Updated to use the send method
        return self.send(
            self.registry_coordinator.functions.registerOperatorWithChurn,
            quorum_numbers,
            socket,
            pubkey_reg_params,
            operator_kick_params,
            churn_approver_signature_with_salt_and_expiry,
            operator_signature_with_salt_and_expiry,
            wait_for_receipt=wait_for_receipt,
        )

    def update_stakes_of_operator_subset_for_all_quorums(
        self, operators: List[str], wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.updateOperators,
            operators,
            wait_for_receipt=wait_for_receipt,
        )

    def deregister_operator(
        self, quorum_numbers: List[int], pubkey: BN254G1Point, wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.deregisterOperator0,
            quorum_numbers,
            wait_for_receipt=wait_for_receipt,
        )

    def update_socket(self, socket: str, wait_for_receipt: bool) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.updateSocket,
            socket,
            wait_for_receipt=wait_for_receipt,
        )

    def set_rewards_initiator(
        self, rewards_initiator_addr: str, wait_for_receipt: bool
    ) -> Optional[Dict]:
        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )

        return self.send(
            service_manager_contract.functions.setRewardsInitiator,
            rewards_initiator_addr,
            wait_for_receipt=wait_for_receipt,
        )

    def set_slashable_stake_lookahead(
        self, quorum_number: int, look_ahead_period: int, wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.stake_registry.functions.setSlashableStakeLookahead,
            quorum_number,
            look_ahead_period,
            wait_for_receipt=wait_for_receipt,
        )

    def set_minimum_stake_for_quorum(
        self, quorum_number: int, minimum_stake: int, wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.stake_registry.functions.setMinimumStakeForQuorum,
            quorum_number,
            minimum_stake,
            wait_for_receipt=wait_for_receipt,
        )

    def create_total_delegated_stake_quorum(
        self,
        operator_set_params: Dict,
        minimum_stake_required: int,
        strategy_params: List[Dict],
        wait_for_receipt: bool,
    ) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.createTotalDelegatedStakeQuorum,
            operator_set_params,
            minimum_stake_required,
            strategy_params,
            wait_for_receipt=wait_for_receipt,
        )

    def create_slashable_stake_quorum(
        self,
        operator_set_params: Dict,
        minimum_stake_required: int,
        strategy_params: List[Dict],
        look_ahead_period: int,
        wait_for_receipt: bool,
    ) -> Optional[Dict]:
        self.logger.info("Creating slashable stake quorum")
        return self.send(
            self.registry_coordinator.functions.createSlashableStakeQuorum,
            operator_set_params,
            minimum_stake_required,
            strategy_params,
            look_ahead_period,
            wait_for_receipt=wait_for_receipt,
        )

    def eject_operator(
        self, operator_address: str, quorum_numbers: List[int], wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.ejectOperator,
            operator_address,
            quorum_numbers,
            wait_for_receipt=wait_for_receipt,
        )

    def set_operator_set_params(
        self, quorum_number: int, operator_set_params: Dict, wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.setOperatorSetParams,
            quorum_number,
            operator_set_params,
            wait_for_receipt=wait_for_receipt,
        )

    def set_churn_approver(
        self, churn_approver_address: str, wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.setChurnApprover,
            churn_approver_address,
            wait_for_receipt=wait_for_receipt,
        )

    def set_ejector(self, ejector_address: str, wait_for_receipt: bool) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.setEjector,
            ejector_address,
            wait_for_receipt=wait_for_receipt,
        )
    


    def modify_strategy_params(
        self,
        quorum_number: int,
        strategy_indices: List[int],
        multipliers: List[int],
        wait_for_receipt: bool,
    ) -> Optional[Dict]:
        return self.send(
            self.stake_registry.functions.modifyStrategyParams,
            quorum_number,
            strategy_indices,
            multipliers,
            wait_for_receipt=wait_for_receipt,
        )

    def set_account_identifier(
        self, account_identifier_address: str, wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.setAccountIdentifier,
            account_identifier_address,
            wait_for_receipt=wait_for_receipt,
        )

    def set_ejection_cooldown(
        self, ejection_cooldown: int, wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.registry_coordinator.functions.setEjectionCooldown,
            ejection_cooldown,
            wait_for_receipt=wait_for_receipt,
        )

    def add_strategies(
        self, quorum_number: int, strategy_params: List[Dict], wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.stake_registry.functions.addStrategies,
            quorum_number,
            strategy_params,
            wait_for_receipt=wait_for_receipt,
        )

    def update_avs_metadata_uri(self, metadata_uri: str, wait_for_receipt: bool) -> Optional[Dict]:
        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )

        return self.send(
            service_manager_contract.functions.updateAVSMetadataURI,
            metadata_uri,
            wait_for_receipt=wait_for_receipt,
        )

    def remove_strategies(
        self, quorum_number: int, indices_to_remove: List[int], wait_for_receipt: bool
    ) -> Optional[Dict]:
        return self.send(
            self.stake_registry.functions.removeStrategies,
            quorum_number,
            indices_to_remove,
            wait_for_receipt=wait_for_receipt,
        )

    def create_avs_rewards_submission(
        self, rewards_submission: List[Dict], wait_for_receipt: bool
    ) -> Optional[Dict]:
        self.logger.info(
            "Creating AVS rewards submission", extra={"rewardsSubmission": rewards_submission}
        )

        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )

        return self.send(
            service_manager_contract.functions.createAVSRewardsSubmission,
            rewards_submission,
            wait_for_receipt=wait_for_receipt,
        )

    def create_operator_directed_avs_rewards_submission(
        self, operator_directed_rewards_submissions: List[Dict], wait_for_receipt: bool
    ) -> Optional[Dict]:
        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )

        return self.send(
            service_manager_contract.functions.createOperatorDirectedAVSRewardsSubmission,
            operator_directed_rewards_submissions,
            wait_for_receipt=wait_for_receipt,
        )
