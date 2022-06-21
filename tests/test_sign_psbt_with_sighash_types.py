import pytest
import threading
from pathlib import Path
from bitcoin_client.ledger_bitcoin import Client, PolicyMapWallet
from bitcoin_client.ledger_bitcoin.exception.errors import NotSupportedError
from bitcoin_client.ledger_bitcoin.psbt import PSBT
from test_utils import has_automation, bip0340

tests_root: Path = Path(__file__).parent

wallet = PolicyMapWallet(
    "",
    "tr(@0)",
    [
        "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**"
    ],
)


# Unlike other transactions, Schnorr signatures are not deterministic (unless the randomness is removed)
# Therefore, for this testcase we hard-code the sighash, and we verify the produced Schnorr signature with the reference bip340 implementation.
sighash_bitcoin_core_all_0 = bytes.fromhex("2221AA462110C77A8E2DD34C3681BAA9BFFF6553B4C609EC7E3D8FF9B1D18D69")
sighash_bitcoin_core_all_1 = bytes.fromhex("D47D3FA22B4F6C50521C49E1A42E8CB10689540A227491A8FC5AD0A6E413063E")
sighash_bitcoin_core_none_0 = bytes.fromhex("965976D58A387369D970F0B6560B144E1B721D41E04675592C41AC35D30D2A56")
sighash_bitcoin_core_none_1 = bytes.fromhex("67E85534A12E4054F4AFAA434D7A7C38123DA6909DF7E45DDB9945F7B8D832D0")
sighash_bitcoin_core_single_0 = bytes.fromhex("F9B834D7FE272F9EACE2FC5F7A97468B024438EF5D55338FC243D5273534A6B5")
sighash_bitcoin_core_single_1 = bytes.fromhex("9A4DDC13C6D0EE10A41D33C6595C63F51AF4C9314387685304F515F790260F78")
sighash_bitcoin_core_all_anyone_0 = bytes.fromhex("DD2D84051CB638446615556A02E9C80D82A772A2EFA10C334C934D0DE0388D5B")
sighash_bitcoin_core_all_anyone_1 = bytes.fromhex("710D9DB2DFABEFA082E82088FB9622BAE7E7F96C67415E2566D6950172A53A44")
sighash_bitcoin_core_none_anyone_0 = bytes.fromhex("8F77861D6EF75C842D7BE121C777C5F1578A1DDF997610DAAE8C3A379A9A8749")
sighash_bitcoin_core_none_anyone_1 = bytes.fromhex("0365A696AF99E7FB721F9001C104EEB8956D5B825CC33E4FFCF4AEFC2A410A52")
sighash_bitcoin_core_single_anyone_0 = bytes.fromhex("05AE9F9FDBAEB91AC1BAD6FC2E1A3CE510B145F07FC8534CCB0FD8FDE9A903C7")
sighash_bitcoin_core_single_anyone_1 = bytes.fromhex("FE0466F5A185B2D466CAC8210C2093615BF7BBFA6DAB6CB5CE3D511E570625CE")

def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sighash_all_sign_psbt(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")

    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    assert len(result[0]) == 64+1
    assert result[0][-1] == 0x01

    assert len(result[0]) == 64+1
    assert result[1][-1] == 0x01

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_0, pubkey0, sig0)
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sighash_all_input_modified(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")

    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_1, pubkey1, sig1) == 0


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sighash_all_output_modfied(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")

    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_1, pubkey1, sig1) == 0


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_none_sign_psbt(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-sign.psbt")

    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    assert len(result[0]) == 64+1
    assert len(result[1]) == 64+1
    assert result[0][-1] == 0x02
    assert result[1][-1] == 0x02

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_0, pubkey0, sig0)
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_none_input_modified(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-sign.psbt")
    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1

    result = client.sign_psbt(psbt, wallet, None)
    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[0][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_1, pubkey1, sig1) == 0


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_none_output_modfied(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1
    
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_0, pubkey0, sig0)
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_single_sign_psbt(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")

    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == 2

    print(result[0])
    print(result[1])

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result[0]) == 64+1
    assert len(result[1]) == 64+1
    assert result[0][-1] == 0x03
    assert result[1][-1] == 0x03

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_0, pubkey0, sig0)
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_single_input_modified(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")
    psbt.tx.vin[1].nSequence = psbt.tx.vin[1].nSequence - 1

    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_1, pubkey1, sig1) == 0 


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_single_output_same_index_modified(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1
    
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_single_output_different_index_modified(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")
    psbt.tx.vout[1].nValue = psbt.tx.vout[1].nValue - 1
    
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_0, pubkey0, sig0)
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_1, pubkey1, sig1) == 0


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_single_3_ins_2_out(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-3-ins-2-outs.psbt")

    with pytest.raises(NotSupportedError):
        client.sign_psbt(psbt, wallet, None)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_all_anyone_sign(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-anyone-can-pay-sign.psbt")

    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == 2

    print(result[0])
    print(result[1])

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result[0]) == 64+1
    assert len(result[1]) == 64+1
    assert result[0][-1] == 0x81
    assert result[1][-1] == 0x81

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_0, pubkey0, sig0)
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_all_anyone_input_changed(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-anyone-can-pay-sign.psbt")
    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1
    
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_all_anyone_output_changed(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-anyone-can-pay-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1
    
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_1, pubkey1, sig1) == 0


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_none_anyone_sign(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-anyone-can-pay-sign.psbt")

    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == 2

    print(result[0])
    print(result[1])

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result[0]) == 64+1
    assert len(result[1]) == 64+1
    assert result[0][-1] == 0x82
    assert result[1][-1] == 0x82

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_0, pubkey0, sig0)
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_none_anyone_input_changed(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-anyone-can-pay-sign.psbt")
    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1
    
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_none_anyone_output_changed(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-anyone-can-pay-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1
    
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_0, pubkey0, sig0)
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_single_anyone_sign(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-anyone-can-pay-sign.psbt")

    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == 2

    print(result[0])
    print(result[1])

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result[0]) == 64+1
    assert len(result[1]) == 64+1
    assert result[0][-1] == 0x83
    assert result[1][-1] == 0x83

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_0, pubkey0, sig0)
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_single_anyone_input_changed(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-anyone-can-pay-sign.psbt")
    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1
    
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_1, pubkey1, sig1)


@has_automation("automations/sign_with_default_wallet_accept_nondefault_sighash.json")
def test_sighash_single_anyone_output_changed(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-anyone-can-pay-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1
    
    result = client.sign_psbt(psbt, wallet, None)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    sig0 = result[0][:-1]
    sig1 = result[1][:-1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_0, pubkey0, sig0) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_1, pubkey1, sig1)


def test_sighash_unsupported(client: Client):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-unsupported.psbt")

    with pytest.raises(NotSupportedError):
        client.sign_psbt(psbt, wallet, None)
