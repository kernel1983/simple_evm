
# reference to https://ethervm.io/
class VM:
    def __init__(self, code) -> None:
        self.code = code
        self.pc = 0
        self.memory = []
        self.stack = []

    def alloc(self, size):
        if len(self.memory) < size:
            for i in range(size - len(self.memory)):
                self.memory.append(0x00)

    def step(self):
        if self.code[self.pc] == 0x00:
            return

        elif self.code[self.pc] == 0x52: # MSTORE offset value
            value = self.stack.pop()
            offset = self.stack.pop()
            print(offset, value)
            self.alloc(ord(offset)+4)
            print(self.memory, self.stack)
            self.pc += 1

        elif self.code[self.pc] == 0x53: # MSTORE8 offset value
            size = self.code[self.pc] - 0x5f

        elif self.code[self.pc] >= 0x60 and self.code[self.pc] <= 0x7f: # PUSHx bytes
            size = self.code[self.pc] - 0x5f
            self.stack.append(self.code[self.pc+1:self.pc+1+size])
            self.pc += 1+size
            print(self.pc, self.stack)

        else:
            print(self.pc, self.code[self.pc])
            raise

