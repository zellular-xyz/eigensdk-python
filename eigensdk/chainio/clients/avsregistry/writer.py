import logging
from typing import List, Optional, Tuple, Dict, Any

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract
from web3.types import TxReceipt
import ecdsa

from eigensdk.chainio.chainio_utils.utils import *
from eigensdk.crypto.bls.attestation import *

from ...utils import send_transaction
from ..elcontracts.reader import ELReader
from typeguard import typechecked


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

    @typechecked
    def register_operator(
        self,
        operator_ecdsa_private_key: ecdsa.SigningKey,
        bls_key_pair: BLSKeyPair,
        quorum_numbers: List[int],
        socket: str,
        wait_for_receipt: bool,
    ) -> Optional[Dict]:

        operator_addr = self.web3.eth.account.from_key(
            operator_ecdsa_private_key.to_string()
        ).address
        self.logger.info(
            "registering operator with the AVS's registry coordinator",
            extra={
                "avs-service-manager": self.service_manager_addr,
                "operator": operator_addr,
                "quorumNumbers": quorum_numbers,
                "socket": socket,
            },
        )

        g1_hashed_msg_to_sign = self.registry_coordinator.functions.pubkeyRegistrationMessageHash(
            operator_addr
        ).call()

        signed_msg = bls_key_pair.sign_hashed_to_curve_message(
            convert_bn254_geth_to_gnark(g1_hashed_msg_to_sign)
        ).g1_point

        g1_pubkey_bn254 = convert_to_bn254_g1_point(bls_key_pair.get_pub_g1())
        g2_pubkey_bn254 = convert_to_bn254_g2_point(bls_key_pair.get_pub_g2())

        pubkey_reg_params = {
            "pubkeyRegistrationSignature": signed_msg,
            "pubkeyG1": g1_pubkey_bn254,
            "pubkeyG2": g2_pubkey_bn254,
        }

        signature_salt = os.urandom(32)
        cur_block_num = self.web3.eth.block_number
        cur_block = self.web3.eth.get_block(cur_block_num)
        sig_valid_for_seconds = 60 * 60  # 1 hour
        signature_expiry = cur_block["timestamp"] + sig_valid_for_seconds

        msg_to_sign = self.el_reader.calculate_operator_avs_registration_digestHash(
            operator_addr,
            self.service_manager_addr,
            signature_salt,
            signature_expiry,
        )

        operator_signature = self.web3.eth.account.sign_message(
            msg_to_sign, operator_ecdsa_private_key
        )
        operator_signature_bytes = operator_signature.signature
        operator_signature_bytes = operator_signature_bytes[:-1] + bytes(
            [operator_signature_bytes[-1] + 27]
        )

        operator_signature_with_salt_and_expiry = {
            "signature": operator_signature_bytes,
            "salt": signature_salt,
            "expiry": signature_expiry,
        }

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.registerOperator(
            no_send_tx_opts,
            quorum_numbers,
            socket,
            pubkey_reg_params,
            operator_signature_with_salt_and_expiry,
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        self.logger.info(
            "successfully registered operator with AVS registry coordinator",
            extra={
                "txHash": receipt["transactionHash"].hex(),
                "avs-service-manager": self.service_manager_addr,
                "operator": operator_addr,
                "quorumNumbers": quorum_numbers,
            },
        )

        return receipt

    @typechecked
    def update_stakes_of_entire_operator_set_for_quorums(
        self,
        operators_per_quorum: List[List[str]],
        quorum_numbers: List[int],
        wait_for_receipt: bool,
    ) -> Optional[Dict]:

        self.logger.info(
            "updating stakes for entire operator set",
            extra={"quorumNumbers": quorum_numbers},
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.updateOperatorsForQuorum(
            no_send_tx_opts, operators_per_quorum, quorum_numbers
        )

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        self.logger.info(
            "successfully updated stakes for entire operator set",
            extra={
                "txHash": receipt["transactionHash"].hex(),
                "quorumNumbers": quorum_numbers,
            },
        )

        return receipt

    @typechecked
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

        signed_msg = bls_key_pair.sign_hashed_to_curve_message(
            convert_bn254_geth_to_gnark(g1_hashed_msg_to_sign)
        ).g1_point

        g1_pubkey_bn254 = convert_to_bn254_g1_point(bls_key_pair.get_pub_g1())
        g2_pubkey_bn254 = convert_to_bn254_g2_point(bls_key_pair.get_pub_g2())

        pubkey_reg_params = {
            "pubkeyRegistrationSignature": signed_msg,
            "pubkeyG1": g1_pubkey_bn254,
            "pubkeyG2": g2_pubkey_bn254,
        }

        signature_salt = os.urandom(32)
        cur_block_num = self.web3.eth.block_number
        cur_block = self.web3.eth.get_block(cur_block_num)
        sig_valid_for_seconds = 60 * 60  # 1 hour
        signature_expiry = cur_block["timestamp"] + sig_valid_for_seconds

        msg_to_sign = self.el_reader.calculate_operator_avs_registration_digestHash(
            operator_addr,
            self.service_manager_addr,
            signature_salt,
            signature_expiry,
        )

        operator_signature = self.web3.eth.account.sign_message(
            msg_to_sign, operator_ecdsa_private_key
        )
        operator_signature_bytes = operator_signature.signature
        operator_signature_bytes = operator_signature_bytes[:-1] + bytes(
            [operator_signature_bytes[-1] + 27]
        )

        operator_signature_with_salt_and_expiry = {
            "signature": operator_signature_bytes,
            "salt": signature_salt,
            "expiry": signature_expiry,
        }

        operator_kick_params = [
            {
                "operator": operator_to_kick,
                "quorumNumber": quorum_numbers_to_kick[i],
            }
            for i, operator_to_kick in enumerate(operators_to_kick)
        ]

        churn_signature_salt = os.urandom(32)
        operator_id = bls_key_pair.get_pub_g1().get_operator_id()
        operator_id_bytes = bytes.fromhex(operator_id[2:])

        churn_msg_to_sign = (
            self.registry_coordinator.functions.calculateOperatorChurnApprovalDigestHash(
                operator_addr,
                operator_id_bytes,
                operator_kick_params,
                churn_signature_salt,
                signature_expiry,
            ).call()
        )

        churn_approval_signature = self.web3.eth.account.sign_message(
            churn_msg_to_sign, churn_approval_ecdsa_private_key
        )
        churn_approval_signature_bytes = churn_approval_signature.signature
        churn_approval_signature_bytes = churn_approval_signature_bytes[:-1] + bytes(
            [churn_approval_signature_bytes[-1] + 27]
        )

        churn_approver_signature_with_salt_and_expiry = {
            "signature": churn_approval_signature_bytes,
            "salt": churn_signature_salt,
            "expiry": signature_expiry,
        }

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.registerOperatorWithChurn(
            no_send_tx_opts,
            quorum_numbers,
            socket,
            pubkey_reg_params,
            operator_kick_params,
            churn_approver_signature_with_salt_and_expiry,
            operator_signature_with_salt_and_expiry,
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        self.logger.info(
            "successfully registered operator with AVS registry coordinator",
            extra={
                "txHash": receipt["transactionHash"].hex(),
                "avs-service-manager": self.service_manager_addr,
                "operator": operator_addr,
                "quorumNumbers": quorum_numbers,
            },
        )

        return receipt

    @typechecked
    def update_stakes_of_operator_subset_for_all_quorums(
        self, operators: List[str], wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info(
            "updating stakes of operator subset for all quorums",
            extra={"operators": operators},
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.updateOperators(
            no_send_tx_opts, operators
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        self.logger.info(
            "successfully updated stakes of operator subset for all quorums",
            extra={
                "txHash": receipt["transactionHash"].hex(),
                "operators": operators,
            },
        )

        return receipt

    @typechecked
    def deregister_operator(
        self, quorum_numbers: List[int], pubkey: BN254G1Point, wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info("deregistering operator with the AVS's registry coordinator")

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.deregisterOperator0(
            no_send_tx_opts, quorum_numbers
        )

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        self.logger.info(
            "successfully deregistered operator with the AVS's registry coordinator",
            extra={"txHash": receipt["transactionHash"].hex()},
        )

        return receipt

    @typechecked
    def update_socket(self, socket: str, wait_for_receipt: bool) -> Optional[Dict]:

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.updateSocket(
            no_send_tx_opts, socket
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def set_rewards_initiator(
        self, rewards_initiator_addr: str, wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info(
            "setting rewards initiator with addr",
            extra={"rewardsInitiatorAddr": rewards_initiator_addr},
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )

        tx = service_manager_contract.functions.setRewardsInitiator(
            no_send_tx_opts, rewards_initiator_addr
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def set_slashable_stake_lookahead(
        self, quorum_number: int, look_ahead_period: int, wait_for_receipt: bool
    ) -> Optional[Dict]:

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.stake_registry.functions.setSlashableStakeLookahead(
            no_send_tx_opts, quorum_number, look_ahead_period
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def set_minimum_stake_for_quorum(
        self, quorum_number: int, minimum_stake: int, wait_for_receipt: bool
    ) -> Optional[Dict]:

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.stake_registry.functions.setMinimumStakeForQuorum(
            no_send_tx_opts, quorum_number, minimum_stake
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def create_total_delegated_stake_quorum(
        self,
        operator_set_params: Dict,
        minimum_stake_required: int,
        strategy_params: List[Dict],
        wait_for_receipt: bool,
    ) -> Optional[Dict]:

        self.logger.info("Creating total delegated stake quorum")

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.createTotalDelegatedStakeQuorum(
            no_send_tx_opts,
            operator_set_params,
            minimum_stake_required,
            strategy_params,
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def create_slashable_stake_quorum(
        self,
        operator_set_params: Dict,
        minimum_stake_required: int,
        strategy_params: List[Dict],
        look_ahead_period: int,
        wait_for_receipt: bool,
    ) -> Optional[Dict]:

        self.logger.info("Creating slashable stake quorum")

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.createSlashableStakeQuorum(
            no_send_tx_opts,
            operator_set_params,
            minimum_stake_required,
            strategy_params,
            look_ahead_period,
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def eject_operator(
        self, operator_address: str, quorum_numbers: List[int], wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info(
            "ejecting operator",
            extra={
                "operator_address": operator_address,
                "quorumNumbers": quorum_numbers,
            },
        )
        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.ejectOperator(
            no_send_tx_opts, operator_address, quorum_numbers
        )

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def set_operator_set_params(
        self, quorum_number: int, operator_set_params: Dict, wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info(
            "setting operator set params for quorum",
            extra={"quorumNumber": quorum_number},
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.setOperatorSetParams(
            no_send_tx_opts, quorum_number, operator_set_params
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def set_churn_approver(
        self, churn_approver_address: str, wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info(
            "setting churn approver",
            extra={"churnApproverAddress": churn_approver_address},
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.setChurnApprover(
            no_send_tx_opts, churn_approver_address
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def set_ejector(self, ejector_address: str, wait_for_receipt: bool) -> Optional[Dict]:

        self.logger.info("setting ejector", extra={"ejectorAddress": ejector_address})

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.setEjector(
            no_send_tx_opts, ejector_address
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def modify_strategy_params(
        self,
        quorum_number: int,
        strategy_indices: List[int],
        multipliers: List[int],
        wait_for_receipt: bool,
    ) -> Optional[Dict]:

        self.logger.info(
            "modifying strategy params for quorum",
            extra={"quorumNumber": quorum_number},
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.stake_registry.functions.modifyStrategyParams(
            no_send_tx_opts,
            quorum_number,
            strategy_indices,
            multipliers,
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def set_account_identifier(
        self, account_identifier_address: str, wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info(
            "setting account identifier",
            extra={"accountIdentifierAddress": account_identifier_address},
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.setAccountIdentifier(
            no_send_tx_opts, account_identifier_address
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def set_ejection_cooldown(
        self, ejection_cooldown: int, wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info("setting ejection cooldown", extra={"ejectionCooldown": ejection_cooldown})

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.registry_coordinator.functions.setEjectionCooldown(
            no_send_tx_opts, ejection_cooldown
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def add_strategies(
        self, quorum_number: int, strategy_params: List[Dict], wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info(
            "adding strategies for quorum",
            extra={"quorumNumber": quorum_number},
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.stake_registry.functions.addStrategies(
            no_send_tx_opts, quorum_number, strategy_params
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def update_avs_metadata_uri(self, metadata_uri: str, wait_for_receipt: bool) -> Optional[Dict]:

        self.logger.info("updating AVS metadata URI", extra={"metadataUri": metadata_uri})

        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = service_manager_contract.functions.updateAVSMetadataURI(
            no_send_tx_opts, metadata_uri
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def remove_strategies(
        self, quorum_number: int, indices_to_remove: List[int], wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info("removing strategies from quorum", extra={"quorumNumber": quorum_number})

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = self.stake_registry.functions.removeStrategies(
            no_send_tx_opts, quorum_number, indices_to_remove
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def create_avs_rewards_submission(
        self, rewards_submission: List[Dict], wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info(
            "creating AVS rewards submission",
            extra={"rewardsSubmission": rewards_submission},
        )

        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = service_manager_contract.functions.createAVSRewardsSubmission(
            no_send_tx_opts, rewards_submission
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt

    @typechecked
    def create_operator_directed_avs_rewards_submission(
        self, operator_directed_rewards_submissions: List[Dict], wait_for_receipt: bool
    ) -> Optional[Dict]:

        self.logger.info(
            "creating operator directed AVS rewards submission",
            extra={"operatorDirectedRewardsSubmissions": operator_directed_rewards_submissions},
        )

        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )

        no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()

        tx = service_manager_contract.functions.createOperatorDirectedAVSRewardsSubmission(
            no_send_tx_opts, operator_directed_rewards_submissions
        ).build_transaction()

        receipt = self.tx_mgr.send(tx, wait_for_receipt)

        return receipt
