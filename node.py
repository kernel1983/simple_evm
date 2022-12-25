# from __future__ import print_function

# import os
# import time
# import hashlib
# import uuid
# import tracemalloc
# import json

# import tornado.options
import tornado.web
import tornado.ioloop
import tornado.httpserver
import tornado.gen
import tornado.escape

import web3
import rlp
import trie

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [(r"/", MainHandler)]
        settings = {"debug":True}

        tornado.web.Application.__init__(self, handlers, **settings)

GENSIS_BLOCK = '0xdac4caf8118a517d53578be2def9a331caabc0115cf805a11d12df1f43ae621f'
transactions_tree = trie.HexaryTrie({})
state_tree = trie.HexaryTrie({})
receipts_tree = trie.HexaryTrie({})

highest_block_height = 0
highest_block_hash = GENSIS_BLOCK
highest_block = {
    'number': hex(highest_block_height),
    'hash': highest_block_hash,
    'parentHash': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'nonce': '0x0000000000000000',
    'transactionsRoot': '0x%s' % transactions_tree.root_hash.hex(),
    'stateRoot': '0x%s' % state_tree.root_hash.hex(),
    'receiptsRoot': '0x%s' % receipts_tree.root_hash.hex(),
    'miner': '0x0000000000000000000000000000000000000000',
    'difficulty': '0x0',
    'totalDifficulty': '0x0',
    'extraData': '0x1234',
    'size': '0x204',
    'gasLimit': '0x1c9c380',
    'gasUsed': '0x0', 
    'timestamp': '0x63a593fb',
    'transactions': [],
    'uncles': [],
    'baseFeePerGas': '0x3b9aca00'
}

blocks_hash = [highest_block_hash]
blocks_data = {highest_block_hash: highest_block}

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        # self.redirect('/dashboard')
        pass

    def post(self):
        self.add_header('access-control-allow-methods', 'OPTIONS, POST')
        self.add_header('access-control-allow-origin', 'moz-extension://52ed146e-8386-4e74-9dae-5fe4e9ae20c8')

        req = tornado.escape.json_decode(self.request.body)
        print(req['method'])
        rpc_id = req['id']
        if req.get('method') == 'eth_chainId':
            resp = {'jsonrpc':'2.0', 'result': hex(520), 'id':rpc_id}

        elif req.get('method') == 'eth_blockNumber':
            global highest_block_height
            # highest_block_height, highest_block_hash, highest_block = chain.get_highest_block()
            resp = {'jsonrpc':'2.0', 'result': hex(highest_block_height), 'id':rpc_id}

        elif req.get('method') == 'eth_getBlockByNumber':
            global highest_block_hash
            params = req['params']
            if params[0] == 'latest':
                block_height = highest_block_height
                block_hash = blocks_hash[block_height]
                block_data = blocks_data[block_hash]
            # result = {
            #     "number":"0x0",
            #     "hash":"0xdac4caf8118a517d53578be2def9a331caabc0115cf805a11d12df1f43ae621f",
            #     "parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
            #     "nonce":"0x0000000000000000",
            #     "mixHash":"0x53c5ae3ce8eefbfad3aca77e5f4e1b19a949b04e2e5ce7a24fbb64422f14f0bf",
            #     "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            #     "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            #     "transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            #     "stateRoot":"0x950cc3b1c26a9cd52a81793977d91eb11603c310375216ccacc4ffe18af72959",
            #     "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            #     "miner":"0x0000000000000000000000000000000000000000",
            #     "difficulty":"0x0","totalDifficulty":"0x0","extraData":"0x1234","size":"0x204","gasLimit":"0x1c9c380",
            #     "gasUsed":"0x0",
            #     "timestamp":"0x63a593fb",
            #     "transactions":[],
            #     "uncles":[],
            #     "baseFeePerGas":"0x3b9aca00"
            # }
            result = block_data

            # highest_block_height, highest_block_hash, highest_block = chain.get_highest_block()
            resp = {'jsonrpc':'2.0', 'result': result, 'id':rpc_id}

        elif req.get('method') == 'eth_getBalance':
            address = web3.Web3.toChecksumAddress(req['params'][0])
            # block_height = req['params'][1]

            # _highest_block_height, highest_block_hash, _highest_block = chain.get_highest_block()
            # db = database.get_conn()
            blockstate_json = db.get(b'blockstate_%s' % highest_block_hash)
            blockstate = tornado.escape.json_decode(blockstate_json)
            print('blockstate', blockstate)
            # print('address', address)

            msg_hash = blockstate.get('subchains', {}).get(address)
            print('msg_hash', msg_hash, address)
            if msg_hash:
                msgstate_json = db.get(b'msgstate_%s' % msg_hash.encode('utf8'))
                msgstate = tornado.escape.json_decode(msgstate_json)
                print('msgstate', msgstate)
                balance = msgstate['balances']['SHA']
            else:
                msg_hash = b'0'*64
                balance = 0

            msg_hashes = blockstate.get('balances_to_collect', {}).get(address, [])
            for msg_hash in msg_hashes:
                print('msg_hash', msg_hash)
                msg_json = db.get(b'msg%s' % msg_hash.encode('utf8'))
                msg = tornado.escape.json_decode(msg_json)
                print('msg', msg)
                if 'eth_raw_tx' in msg[chain.MSG_DATA]:
                    raw_tx = msg[chain.MSG_DATA]['eth_raw_tx']
                    tx, tx_from, tx_to, _tx_hash = tx_info(raw_tx)
                    if tx_to == address:
                        balance += int(tx.value/10**18)

            resp = {'jsonrpc':'2.0', 'result': hex(balance*(10**18)), 'id':rpc_id}

        elif req.get('method') == 'eth_getTransactionReceipt':
            msg_hash = req['params'][0]
            # db = database.get_conn()
            msg_json = db.get(b'msg%s' % msg_hash.encode('utf8'))
            print(msg_json)
            msg = tornado.escape.json_decode(msg_json)

            result = {
                'transactionHash': msg_hash,
                'transactionIndex': 0,
                'blockHash': msg_hash,
                'blockNumber': 0,
                'from': msg[chain.SENDER],
                'to': msg[chain.RECEIVER],
                'cumulativeGasUsed': 0,
                'gasUsed':0,
                'contractAddress': '',
                'logs': [],
                'logsBloom': ''
            }
            resp = {'jsonrpc':'2.0', 'result': result, 'id': rpc_id}

        elif req.get('method') == 'eth_getCode':
            resp = {'jsonrpc':'2.0', 'result': '0x0208', 'id': rpc_id}

        elif req.get('method') == 'eth_gasPrice':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'eth_estimateGas':
            resp = {'jsonrpc':'2.0', 'result': '0x5208', 'id': rpc_id}

        elif req.get('method') == 'eth_getTransactionCount':
            address = web3.Web3.toChecksumAddress(req['params'][0])
            # db = database.get_conn()
            prev_hash = db.get(b'chain%s' % address.encode('utf8'))
            count = 0
            if prev_hash:
                msg_json = db.get(b'msg%s' % prev_hash)
                # print(msg_json)
                msg = tornado.escape.json_decode(msg_json)
                # print(msg)
                count = msg[chain.MSG_HEIGHT]

            resp = {'jsonrpc':'2.0', 'result': hex(count+1), 'id': rpc_id}

        elif req.get('method') == 'eth_getBlockByHash':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'eth_sendRawTransaction':
            raw_tx = req['params'][0]
            # print('raw_tx', raw_tx)
            tx, tx_from, tx_to, _tx_hash = tx_info(raw_tx)
            print('nonce', tx.nonce)
            db = database.get_conn()
            prev_hash = db.get(b'chain%s' % tx_from.encode('utf8'))
            if prev_hash:
                msg_json = db.get(b'msg%s' % prev_hash)
                # print(msg_json)
                msg = tornado.escape.json_decode(msg_json)
                # print(msg)
                assert msg[chain.MSG_HEIGHT] + 1 == tx.nonce
            else:
                prev_hash = b'0'*64
                assert 1 == tx.nonce

            # _msg_header, block_hash, prev_hash, sender, receiver, height, data, timestamp, signature = seq
            data = {'eth_raw_tx': raw_tx}
            data_json = json.dumps(data)
            new_timestamp = time.time()
            block_hash_obj = hashlib.sha256((prev_hash.decode('utf8') + tx_from + tx_to + str(tx.nonce) + data_json + str(new_timestamp)).encode('utf8'))
            block_hash = block_hash_obj.hexdigest()
            signature = 'eth'

            chain.new_subchain_block(['NEW_SUBCHAIN_BLOCK', block_hash, prev_hash.decode('utf8'), tx_from, tx_to, tx.nonce, data, new_timestamp, signature])
            tree.forward(['NEW_SUBCHAIN_BLOCK', block_hash, prev_hash.decode('utf8'), tx_from, tx_to, tx.nonce, data, new_timestamp, signature])

            resp = {'jsonrpc':'2.0', 'result': '0x%s' % block_hash, 'id': rpc_id}

        elif req.get('method') == 'eth_call':
            resp = {'jsonrpc':'2.0', 'result': '0x0', 'id': rpc_id}

        elif req.get('method') == 'web3_clientVersion':
            resp = {'jsonrpc':'2.0', 'result': 'SimpleEVM', 'id': rpc_id}

        elif req.get('method') == 'net_version':
            resp = {'jsonrpc':'2.0', 'result': hex(520),'id': rpc_id}

        elif req.get('method') == 'evm_snapshot':
            resp = {'jsonrpc':'2.0', 'result': hex(1),'id': rpc_id}

        print(resp)
        self.write(tornado.escape.json_encode(resp))


def main():
    server = Application()
    server.listen(8546, '0.0.0.0')
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    main()

