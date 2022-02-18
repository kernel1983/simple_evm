
# reference to https://ethervm.io/
class VM:
    def __init__(self, code, msg) -> None:
        self.msg = msg
        self.code = code
        self.pc = 0
        self.memory = []
        self.stack = []

    def alloc(self, size):
        if len(self.memory) < size:
            for i in range(size - len(self.memory)):
                self.memory.append(0x00)

    def step(self):
        print('Pc:', self.pc, 'Opcode:', hex(self.code[self.pc]))
        print('Stack before:', [[hex(b) for b in s] for s in self.stack])
        print('Mem before:', self.memory)

        if self.code[self.pc] == 0x00:
            return

        elif self.code[self.pc] == 0x01: # ADD
            pass

        elif self.code[self.pc] == 0x02: # MUL
            pass

        elif self.code[self.pc] == 0x03: # SUB
            pass

        elif self.code[self.pc] == 0x04: # DIV
            b = self.stack.pop()
            right = int.from_bytes(b, 'little')
            a = self.stack.pop()
            left = int.from_bytes(a, 'little')
            result = int(right/left).to_bytes(4, 'little')
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
            b = self.stack.pop()
            right = int.from_bytes(b, 'little')
            a = self.stack.pop()
            left = int.from_bytes(a, 'little')
            self.stack.append(bytes([left < right]))
            self.pc += 1

        elif self.code[self.pc] == 0x16: # AND
            pass

        elif self.code[self.pc] == 0x17: # OR
            pass

        elif self.code[self.pc] == 0x18: # XOR
            pass

        elif self.code[self.pc] == 0x19: # NOT
            pass

        elif self.code[self.pc] == 0x35: # CALLDATALOAD
            i = self.stack.pop()
            mc = int.from_bytes(i, 'little')
            result = self.msg[mc:mc+32]
            result += bytes([0]*(32-len(result)))
            self.stack.append(result)
            self.pc += 1

        elif self.code[self.pc] == 0x36: # CALLDATASIZE
            self.stack.append(bytes([len(self.msg)]))
            self.pc += 1

        elif self.code[self.pc] == 0x52: # MSTORE offset value
            value = self.stack.pop()
            offset = self.stack.pop()
            print(offset, value)
            mc = int.from_bytes(offset, 'little')
            self.alloc(mc + 4)
            for b in value:
                self.memory[mc] = b
                mc += 1
            self.pc += 1

        elif self.code[self.pc] == 0x53: # MSTORE8 offset value
            pass

        elif self.code[self.pc] == 0x54: # SLOAD
            pass

        elif self.code[self.pc] == 0x57: # JUMPI
            dist = self.stack.pop()
            cond = self.stack.pop()
            if(ord(cond)):
                self.pc = int.from_bytes(dist, 'little')
            else:
                self.pc += 1

        elif self.code[self.pc] == 0x5b: # JUMPDEST
            self.pc += 1

        elif self.code[self.pc] >= 0x60 and self.code[self.pc] <= 0x7f: # PUSHx bytes
            size = self.code[self.pc] - 0x5f
            self.stack.append(self.code[self.pc+1:self.pc+1+size])
            self.pc += 1+size

        else:
            raise

        print('Stack after:', [[hex(b) for b in s] for s in self.stack])
        print('Mem after:', self.memory)
        print('------\n')

