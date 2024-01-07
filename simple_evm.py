import binascii

from eth_hash.auto import keccak

UINT_256_MAX = 2**256 - 1
UINT_256_CEILING = 2**256
UINT_255_MAX = 2**255 - 1
UINT_255_CEILING = 2**255

# reference to https://ethervm.io/
class VM:
    def __init__(self, state, msg) -> None:
        self.msg = msg
        self.state = state
        code = state[self.msg['address']]['code']
        if type(code) is bytes:
            self.code = code
        else:
            self.code = binascii.unhexlify(code.replace('0x', ''))
        self.pc = 0
        self.memory = []
        self.stack = []

    def alloc(self, size):
        if len(self.memory) < size:
            for i in range(size - len(self.memory)):
                self.memory.append(0x00)

    def step(self):
        print('------')
        print('Pc:', self.pc, 'Opcode:', hex(self.code[self.pc]))
        # print('Stack before:')
        # for i in self.stack:
        #     print('', binascii.hexlify(i))
        # print('Mem before:', self.memory)

        if self.code[self.pc] == 0x00: # STOP
            print('STOP')
            return

        elif self.code[self.pc] == 0x01: # ADD
            '''
            branch action :
                for exec the "ADD" op
            example : 0x03 0x02 ADD => 0x05
            '''
            print('ADD')
            # pop the op number
            last_bytes = self.stack.pop() # the last item
            first_bytes = self.stack.pop()

            # the endian use the "big"
            last_num = int.from_bytes(last_bytes, 'big', signed=True)# the signed must set True for the negative number
            first_num = int.from_bytes(first_bytes, 'big', signed=True)

            # computer the result  ! note the value 32 is for make the bytes len == 32
            result = (first_num + last_num).to_bytes(32, 'big', signed=True)# the signed must set True for the negative number

            # push to the stack (the result)
            self.stack.append(result)
            self.pc += 1

        elif self.code[self.pc] == 0x02: # MUL
            print('MUL')
            pass

        elif self.code[self.pc] == 0x03: # SUB
            '''
            branch action :
                for exec the "SUB" op
            example : 0x03 0x02 SUB => 0x01
            '''
            print('SUB', self.stack)
            # pop the op number
            a = self.stack.pop() # the last item
            b = self.stack.pop()
            left = int.from_bytes(b, 'big')
            right = int.from_bytes(a, 'big')
            print('SUB', left, right)
            if left - right < 0:
                result = (left - right + 2**256).to_bytes(32, 'big')
            else:
                result = (left - right).to_bytes(32, 'big')

            # push to the stack (the result)
            self.stack.append(result)
            self.pc += 1

        elif self.code[self.pc] == 0x04: # DIV
            a = self.stack.pop()
            left = int.from_bytes(a, 'big')
            b = self.stack.pop()
            right = int.from_bytes(b, 'big')
            result = int(left/right).to_bytes(32, 'big')
            self.stack.append(result)
            self.pc += 1

        # elif self.code[self.pc] == 0x05: # SDIV
        #     pass

        # elif self.code[self.pc] == 0x06: # MOD
        #     pass

        # elif self.code[self.pc] == 0x07: # SMOD
        #     pass

        # elif self.code[self.pc] == 0x08: # ADDMOD
        #     pass

        # elif self.code[self.pc] == 0x09: # MULMOD
        #     pass

        # elif self.code[self.pc] == 0x0a: # EXP
        #     pass

        # elif self.code[self.pc] == 0x0b: # SIGNEXTEND
        #     pass

        elif self.code[self.pc] == 0x10: # LT
            print('LT')
            a = self.stack.pop()
            left = int.from_bytes(a, 'big')
            b = self.stack.pop()
            right = int.from_bytes(b, 'big')
            self.stack.append(bytes([0]*31+[left < right]))
            self.pc += 1

        elif self.code[self.pc] == 0x11: # GT
            print('GT')
            a = self.stack.pop()
            left = int.from_bytes(a, 'big')
            b = self.stack.pop()
            right = int.from_bytes(b, 'big')
            self.stack.append(bytes([0]*31+[left > right]))
            self.pc += 1

        elif self.code[self.pc] == 0x12: # SLT
            print('SLT')
            a = self.stack.pop()
            left = int.from_bytes(a, 'big')
            if left > UINT_255_MAX:
                return left - UINT_256_CEILING
            b = self.stack.pop()
            right = int.from_bytes(b, 'big')
            if right > UINT_255_MAX:
                return right - UINT_256_CEILING
            print(left, right)
            self.stack.append(bytes([0]*31+[left < right]))
            self.pc += 1

        elif self.code[self.pc] == 0x13: # SGT
            print('SGT')
            a = self.stack.pop()
            left = int.from_bytes(a, 'big')
            if left > UINT_255_MAX:
                return left - UINT_256_CEILING
            b = self.stack.pop()
            right = int.from_bytes(b, 'big')
            if right > UINT_255_MAX:
                return right - UINT_256_CEILING
            self.stack.append(bytes([0]*31+[left > right]))
            self.pc += 1

        elif self.code[self.pc] == 0x14: # EQ
            print('EQ')
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(bytes([0]*31+[a == b]))
            self.pc += 1

        elif self.code[self.pc] == 0x15: # ISZERO
            print('ISZERO')
            bs = self.stack.pop()
            result = 1
            for b in bs:
                if b > 0:
                    result = 0
                    break
            self.stack.append(result.to_bytes(32, 'big'))
            self.pc += 1

        elif self.code[self.pc] == 0x16: # AND
            b = self.stack.pop()
            a = self.stack.pop()
            print('AND', b, a)

            result = []
            for i in range(32):
                result.append(b[i] & a[i])
            self.stack.append(bytes(result))
            self.pc += 1

        elif self.code[self.pc] == 0x17: # OR
            print('OR')
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(bytes([a[i] | b[i] for i in range(32)]))
            self.pc += 1

        # elif self.code[self.pc] == 0x18: # XOR
        #     pass

        elif self.code[self.pc] == 0x19: # NOT
            print('NOT')
            print(self.stack)
            obj = self.stack.pop()
            self.stack.append(bytes([255-i for i in obj]))
            print(self.stack)
            self.pc += 1

        # elif self.code[self.pc] == 0x1a: # BYTE
        #     pass

        elif self.code[self.pc] == 0x1b: # SHL
            print('SHL')
            i = self.stack.pop()
            shift = int.from_bytes(i, 'big')
            print('shift', shift)
            i = self.stack.pop()
            value = int.from_bytes(i, 'big')
            print('value', value)
            if shift >= 256:
                result = 0
            else:
                result = value << shift
            self.stack.append(result.to_bytes(32, 'big'))
            self.pc += 1

        elif self.code[self.pc] == 0x1c: # SHR
            print('SHR')
            i = self.stack.pop()
            shift = int.from_bytes(i, 'big')
            print('shift', shift)
            i = self.stack.pop()
            value = int.from_bytes(i, 'big')
            print('value', value)
            if shift >= 256:
                result = 0
            else:
                result = value >> shift
            self.stack.append(result.to_bytes(32, 'big'))
            self.pc += 1

        # elif self.code[self.pc] == 0x1d: # SAR
        #     print('SAR')

        elif self.code[self.pc] == 0x20: # SHA3
            print('SHA3')
            offset = self.stack.pop()
            mc = int.from_bytes(offset, 'big')
            length = self.stack.pop()
            l = int.from_bytes(length, 'big')
            data = bytes(self.memory[mc:mc+l])
            hash = keccak(data)
            self.stack.append(hash)
            print('SHA3', data, hash)
            self.pc += 1

        elif self.code[self.pc] == 0x30: # ADDRESS
            print('ADDRESS')
            self.stack.append(self.msg['address'])
            self.pc += 1

        elif self.code[self.pc] == 0x31: # BALANCE
            print('BALANCE')
            address = self.stack.pop()
            self.stack.append(self.state[address]['balance'].to_bytes(32, 'big'))
            self.pc += 1

        elif self.code[self.pc] == 0x32: # ORIGIN
            print('ORIGIN')
            self.stack.append(self.msg['origin'])
            self.pc += 1

        elif self.code[self.pc] == 0x33: # CALLER
            print('CALLER')
            self.stack.append(self.msg['sender'])
            self.pc += 1

        elif self.code[self.pc] == 0x34: # CALLVALUE
            print('CALLVALUE')
            self.stack.append(self.msg['value'].to_bytes(32, 'big'))
            print('CALLVALUE', self.msg)
            self.pc += 1

        elif self.code[self.pc] == 0x35: # CALLDATALOAD
            print('CALLDATALOAD')
            i = self.stack.pop()
            mc = int.from_bytes(i, 'big')
            data = self.msg['data'][mc:mc+32]
            result = data+bytes([0]*(32-len(data)))
            self.stack.append(result)
            self.pc += 1

        elif self.code[self.pc] == 0x36: # CALLDATASIZE
            print('CALLDATASIZE')
            self.stack.append(len(self.msg['data']).to_bytes(32, 'big'))
            self.pc += 1

        # elif self.code[self.pc] == 0x37: # CALLDATACOPY
        #     print('CALLDATACOPY')
        #     pass

        elif self.code[self.pc] == 0x38: # CODESIZE
            print('CODESIZE')
            self.stack.append(len(self.code).to_bytes(32, 'big'))
            self.pc += 1

        elif self.code[self.pc] == 0x39: # CODECOPY
            print('CODECOPY')
            dest_offset = int.from_bytes(self.stack.pop(), 'big')
            offset = int.from_bytes(self.stack.pop(), 'big')
            length = int.from_bytes(self.stack.pop(), 'big')
            print(dest_offset, offset, length)
            # print(len(self.code[offset:offset+length]))

            self.alloc(dest_offset+length)
            for b in self.code[offset:offset+length]:
                self.memory[dest_offset] = b
                dest_offset += 1
            self.pc += 1

        elif self.code[self.pc] == 0x50: # POP
            print('POP')
            self.stack.pop()
            self.pc += 1

        elif self.code[self.pc] == 0x51: # MLOAD
            print('MLOAD')
            offset = self.stack.pop()
            mc = int.from_bytes(offset, 'big')
            data = bytes(self.memory[mc:mc+32])
            result = data+bytes([0]*(32-len(data)))
            self.stack.append(result)
            self.pc += 1

        elif self.code[self.pc] == 0x52: # MSTORE offset value
            print('MSTORE')
            offset = self.stack.pop()
            print('MSTORE offset', offset)
            value = self.stack.pop()
            print('MSTORE value', value)
            mc = int.from_bytes(offset, 'big')
            self.alloc(mc + 32)
            for b in value:
                self.memory[mc] = b
                mc += 1
            self.pc += 1

        elif self.code[self.pc] == 0x53: # MSTORE8 offset value
            print('MSTORE8')
            offset = self.stack.pop()
            value = self.stack.pop()
            mc = int.from_bytes(offset, 'big')
            self.alloc(mc + 1)
            self.memory[mc] = value[0]
            self.pc += 1

        elif self.code[self.pc] == 0x54: # SLOAD
            print('SLOAD')
            key = self.stack.pop()
            print(self.state[self.msg['address']]['storage'])
            value = self.state[self.msg['address']]['storage'].get(key.hex(), b'\x00'*32)
            self.stack.append(value)
            self.pc += 1

        elif self.code[self.pc] == 0x55: # SSTORE
            print('SSTORE')
            key = self.stack.pop()
            value = self.stack.pop()
            print(self.state[self.msg['address']]['storage'])
            self.state[self.msg['address']]['storage'][key.hex()] = value
            print(self.state[self.msg['address']]['storage'])
            self.pc += 1

        elif self.code[self.pc] == 0x56: # JUMP
            print('JUMP')
            dist = self.stack.pop()
            self.pc = int.from_bytes(dist, 'big')

        elif self.code[self.pc] == 0x57: # JUMPI
            print('JUMPI')
            dist = self.stack.pop()
            cond = self.stack.pop()
            if(int.from_bytes(cond, 'big')):
                self.pc = int.from_bytes(dist, 'big')
            else:
                self.pc += 1

        elif self.code[self.pc] == 0x5b: # JUMPDEST
            print('JUMPDEST', self.pc)
            self.pc += 1

        elif self.code[self.pc] >= 0x60 and self.code[self.pc] <= 0x7f: # PUSHx
            size = self.code[self.pc] - 0x5f
            print('PUSH', size)
            print('PUSH', bytes(self.code[self.pc+1:self.pc+1+size]))
            self.stack.append(bytes([0]*(32-size)) + self.code[self.pc+1:self.pc+1+size])
            self.pc += size+1

        elif self.code[self.pc] >= 0x80 and  self.code[self.pc] <= 0x8f: # DUPx
            size = self.code[self.pc] - 0x7f
            print('DUP', size)
            self.stack.append(self.stack[-size])
            self.pc += 1

        elif self.code[self.pc] >= 0x90 and  self.code[self.pc] <= 0x9f: # SWAPx
            size = self.code[self.pc] - 0x8f
            print('SWAP', size)
            self.stack[-1], self.stack[-1-size] = self.stack[-1-size], self.stack[-1] 
            self.pc += 1

        # elif self.code[self.pc] >= 0xA0 and  self.code[self.pc] <= 0xA4: # LOGx
        #     pass

        elif self.code[self.pc] == 0xf3: # RETURN
            print('RETURN')
            '''
            branch action :
                for exec the "RETURN" op
            example : memory[offset:offset+length]
            '''
            # pop the op number
            offset_bytes = self.stack.pop()
            length_bytes = self.stack.pop()

            # the endian use the "big"
            offset_num = int.from_bytes(offset_bytes, 'big', signed=True) # the signed must set True for the negative number
            length_num = int.from_bytes(length_bytes, 'big', signed=True)
            print('RETURN', offset_num, length_num)

            # ! I think should assert the offset and the length must be positive number

            # return the value
            return bytes(self.memory[offset_num : offset_num + length_num]).hex()

        elif self.code[self.pc] == 0xfd: # REVERT
            print('REVERT')
            # pop the op number
            offset_bytes = self.stack.pop()
            length_bytes = self.stack.pop()

            # the endian use the "big"
            offset_num = int.from_bytes(offset_bytes, 'big', signed=True) # the signed must set True for the negative number
            length_num = int.from_bytes(length_bytes, 'big', signed=True)

            # return the value
            return 'REVERT', self.memory[offset_num : offset_num + length_num]

        else:
            raise

        print('Stack after:')
        for i in self.stack:
            print('', binascii.hexlify(i))
        print('Mem after:', self.memory)

