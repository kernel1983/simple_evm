import binascii

UINT_256_MAX = 2**256 - 1

# reference to https://ethervm.io/
class VM:
    def __init__(self, state, msg) -> None:
        self.msg = msg
        self.state = state
        self.code = state[self.msg['address']]['code']
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
        print('Stack before:')
        for i in self.stack:
            print('', binascii.hexlify(i))
        print('Mem before:', self.memory)

        if self.code[self.pc] == 0x00: # STOP
            print('STOP')
            return

        elif self.code[self.pc] == 0x01: # ADD
            '''
            branch action :
                for exec the "ADD" op
            example : 0x03 0x02 ADD => 0x05
            '''
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
            pass

        elif self.code[self.pc] == 0x03: # SUB
            '''
            branch action :
                for exec the "SUB" op
            example : 0x03 0x02 SUB => 0x01
            '''
            # pop the op number
            last_bytes = self.stack.pop() # the last item
            first_bytes = self.stack.pop()

            # the endian use the "big"
            last_num = int.from_bytes(last_bytes, 'big', signed=True) # the signed must set True for the negative number
            first_num = int.from_bytes(first_bytes, 'big', signed=True)

            # computer the result  ! note the value 32 is for make the bytes len == 32
            result = (first_num - last_num).to_bytes(32, 'big', signed=True) # the signed must set True for the negative number

            # push to the stack (the result)
            self.stack.append(result)
            self.pc += 1

        elif self.code[self.pc] == 0x04: # DIV
            b = self.stack.pop()
            right = int.from_bytes(b, 'big')
            a = self.stack.pop()
            left = int.from_bytes(a, 'big')
            result = int(right/left).to_bytes(32, 'big')
            self.stack.append(result)
            self.pc += 1

        elif self.code[self.pc] == 0x05: # SDIV
            pass

        elif self.code[self.pc] == 0x06: # MOD
            pass

        elif self.code[self.pc] == 0x07: # SMOD
            pass

        elif self.code[self.pc] == 0x08: # ADDMOD
            pass

        elif self.code[self.pc] == 0x09: # MULMOD
            pass

        elif self.code[self.pc] == 0x0a: # EXP
            pass

        elif self.code[self.pc] == 0x0b: # SIGNEXTEND
            pass

        elif self.code[self.pc] == 0x10: # LT
            print('LT')
            b = self.stack.pop()
            right = int.from_bytes(b, 'big')
            a = self.stack.pop()
            left = int.from_bytes(a, 'big')
            self.stack.append(bytes([0]*31+[left < right]))
            self.pc += 1

        elif self.code[self.pc] == 0x11: # GT
            print('GT')
            b = self.stack.pop()
            right = int.from_bytes(b, 'big')
            a = self.stack.pop()
            left = int.from_bytes(a, 'big')
            self.stack.append(bytes([0]*31+[left > right]))
            self.pc += 1

        elif self.code[self.pc] == 0x12: # SLT
            pass

        elif self.code[self.pc] == 0x13: # SLT
            pass

        elif self.code[self.pc] == 0x14: # EQ
            b = self.stack.pop()
            a = self.stack.pop()
            self.stack.append(bytes([a == b]))
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

            result = []
            for i in range(32):
                result.append(b[i] & a[i])
            self.stack.append(bytes(result))
            self.pc += 1

        elif self.code[self.pc] == 0x17: # OR
            pass

        elif self.code[self.pc] == 0x18: # XOR
            pass

        elif self.code[self.pc] == 0x19: # NOT
            pass

        elif self.code[self.pc] == 0x1a: # BYTE
            pass

        elif self.code[self.pc] == 0x1b: # SHL
            pass

        elif self.code[self.pc] == 0x1c: # SHR
            i = self.stack.pop()
            value = int.from_bytes(i, 'big')
            i = self.stack.pop()
            shift = int.from_bytes(i, 'big')
            if shift >= 256:
                result = 0
            else:
                result = (value >> shift) & UINT_256_MAX
            self.stack.append(result.to_bytes(32, 'big'))
            self.pc += 1

        elif self.code[self.pc] == 0x1d: # SAR
            pass

        elif self.code[self.pc] == 0x20: # SHA3
            pass

        elif self.code[self.pc] == 0x30: # ADDRESS
            self.stack.append(self.msg['address'])
            self.pc += 1

        elif self.code[self.pc] == 0x31: # BALANCE
            address = self.stack.pop()
            self.stack.append(self.state[address]['balance'].to_bytes(32, 'big'))
            self.pc += 1

        elif self.code[self.pc] == 0x32: # ORIGIN
            self.stack.append(self.msg['origin'])
            self.pc += 1

        elif self.code[self.pc] == 0x33: # CALLER
            self.stack.append(self.msg['sender'])
            self.pc += 1

        elif self.code[self.pc] == 0x34: # CALLVALUE
            self.stack.append(self.msg['value'].to_bytes(32, 'big'))
            self.pc += 1

        elif self.code[self.pc] == 0x35: # CALLDATALOAD
            i = self.stack.pop()
            mc = int.from_bytes(i, 'big')
            data = self.msg['data'][mc:mc+32]
            result = data+bytes([0]*(32-len(data)))
            self.stack.append(result)
            self.pc += 1

        elif self.code[self.pc] == 0x36: # CALLDATASIZE
            self.stack.append(len(self.msg['data']).to_bytes(32, 'big'))
            self.pc += 1

        elif self.code[self.pc] == 0x50: # POP
            self.stack.pop()
            self.pc += 1

        elif self.code[self.pc] == 0x51: # MLOAD
            offset = self.stack.pop()
            mc = int.from_bytes(offset, 'big')
            data = bytes(self.memory[mc:mc+32])
            result = data+bytes([0]*(32-len(data)))
            self.stack.append(result)
            self.pc += 1

        elif self.code[self.pc] == 0x52: # MSTORE offset value
            offset = self.stack.pop()
            value = self.stack.pop()
            mc = int.from_bytes(offset, 'big')
            self.alloc(mc + 32)
            for b in value:
                self.memory[mc] = b
                mc += 1
            self.pc += 1

        elif self.code[self.pc] == 0x53: # MSTORE8 offset value
            offset = self.stack.pop()
            value = self.stack.pop()
            mc = int.from_bytes(offset, 'big')
            self.alloc(mc + 1)
            self.memory[mc] = value[0]
            self.pc += 1

        elif self.code[self.pc] == 0x54: # SLOAD
            pass

        elif self.code[self.pc] == 0x55: # SSTORE
            pass

        elif self.code[self.pc] == 0x56: # JUMP
            dist = self.stack.pop()
            self.pc = int.from_bytes(dist, 'big')

        elif self.code[self.pc] == 0x57: # JUMPI
            dist = self.stack.pop()
            cond = self.stack.pop()
            if(int.from_bytes(cond, 'big')):
                self.pc = int.from_bytes(dist, 'big')
            else:
                self.pc += 1

        elif self.code[self.pc] == 0x5b: # JUMPDEST
            self.pc += 1

        elif self.code[self.pc] >= 0x60 and self.code[self.pc] <= 0x7f: # PUSHx
            size = self.code[self.pc] - 0x5f
            self.stack.append(bytes([0]*(32-size)) + self.code[self.pc+1:self.pc+1+size])
            self.pc += size+1

        elif self.code[self.pc] >= 0x80 and  self.code[self.pc] <= 0x8f: # DUPx
            size = self.code[self.pc] - 0x7f
            self.stack.append(self.stack[-size])
            self.pc += 1

        elif self.code[self.pc] >= 0x90 and  self.code[self.pc] <= 0x9f: # SWAPx
            size = self.code[self.pc] - 0x8f
            self.stack[-1], self.stack[-1-size] = self.stack[-1-size], self.stack[-1] 
            self.pc += 1

        elif self.code[self.pc] >= 0xA0 and  self.code[self.pc] <= 0xA4: # LOGx
            pass

        elif self.code[self.pc] == 0xf3: # RETURN
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

            # ! I think should assert the offset and the length must be positive number

            # return the value
            return self.memory[offset_num : offset_num + length_num]

        elif self.code[self.pc] == 0xfd: # REVERT
            print('REVERT')
            # pop the op number
            offset_bytes = self.stack.pop()
            length_bytes = self.stack.pop()

            # the endian use the "big"
            offset_num = int.from_bytes(offset_bytes, 'big', signed=True) # the signed must set True for the negative number
            length_num = int.from_bytes(length_bytes, 'big', signed=True)

            # ! I think should assert the offset and the length must be positive number

            # return the value
            return self.memory[offset_num : offset_num + length_num]

        else:
            raise

        print('Stack after:')
        for i in self.stack:
            print('', binascii.hexlify(i))
        print('Mem after:', self.memory)

