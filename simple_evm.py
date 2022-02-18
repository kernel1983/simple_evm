
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

        elif self.code[self.pc] == 0x10: # LT
            b = self.stack.pop()
            right = int.from_bytes(b, 'little')
            a = self.stack.pop()
            left = int.from_bytes(a, 'little')
            self.stack.append(bytes([left < right]))
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

