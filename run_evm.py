
import binascii

from eth_hash.auto import keccak

from simple_evm import VM

"""
pragma solidity ^0.4.24;

contract GetValues {
    function getMeaningOfLife() public pure returns (uint256) {
        return 42;
    }
    function getGasPrice() public view returns (uint256) {
        return tx.gasprice;
    }
    function getBalance() public view returns (uint256) {
        return msg.sender.balance;
    }
    function doRevert() public pure {
        revert("always reverts");
    }
    function useLotsOfGas() public view {
        uint size;
        for (uint i = 0; i < 2**255; i++){
            assembly {
                size := extcodesize(0)
            }
        }
    }
}
"""

print([hex(i) for i in keccak(b'getBalance()')[:4]])

ADDRESS = b'\x85\x82\xa2\x89\x02\xb9\xae\x93\xfc\x03\xdd\xb4\xae\xae\xe1\x8e\x85\x93\x12\xc1'
SENDER = b'\xae\x03\x02\x18\x87\xc2\x22\x37\x6f\x12\xca\xf0\x21\x44\xa1\x2f\x19\x19\x92\xcf'
code_hex = '60806040526004361061006c5763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166312065fe08114610071578063455259cb14610098578063858af522146100ad57806395dd7a55146100c2578063afc874d2146100d9575b600080fd5b34801561007d57600080fd5b506100866100ee565b60408051918252519081900360200190f35b3480156100a457600080fd5b506100866100f3565b3480156100b957600080fd5b506100866100f7565b3480156100ce57600080fd5b506100d76100fc565b005b3480156100e557600080fd5b506100d7610139565b333190565b3a90565b602a90565b6000805b7f80000000000000000000000000000000000000000000000000000000000000008110156101355760003b9150600101610100565b5050565b604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152600e60248201527f616c776179732072657665727473000000000000000000000000000000000000604482015290519081900360640190fd00a165627a7a72305820645df686b4a16d5a69fc6d841fc9ad700528c14b35ca5629e11b154a9d3dff890029'
code_bytes = binascii.unhexlify(code_hex)
msg = {
    'data': b'\x12\x06\x5f\xe0',
    'value': 0,
    'origin': SENDER,
    'sender': SENDER,
    'address': ADDRESS
}

state = {
    ADDRESS: {
        "balance": 100000000000000000,
        "nonce": 0,
        'code': code_bytes,
        "storage": {}
    },
    SENDER: {
        "balance": 10,
        "nonce": 0,
        "storage": {}
    },
}

m = VM(state, msg)
pc = None
while pc != m.pc:
    pc = m.pc
    r = m.step()
    if r:
        print("return value", r)
