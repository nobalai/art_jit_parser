import argparse
import logging
import os
from capstone import *
import sys
_python3 = sys.version_info.major == 3

logging.basicConfig(level=logging.INFO)

JIT_MAGIC = b'\x44\x54\x69\x4a'  # "JiTD"
JIT_VERSION = 1

ELF_MACH_ARM = 0x28
ELF_MACH_ARM64 = 0xb7
ELF_MACH_IA32 = 0x3
ELF_MACH_X64 = 0x3E

elfMachCode = 0


def to_hex2(s):
    if _python3:
        r = "".join("{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
    else:
        r = "".join("{0:02x}".format(ord(c)) for c in s)
    while r[0] == '0': r = r[1:]
    return r


class JitMethod:
    def __init__(self, elfMachCode):
        self.mach = elfMachCode
        self.event = -1  # load = 0, move = 1, debuginfo = 2, close = 4
        self.size = 0
        self.timestamp = 0
        self.pid = 0
        self.tid = 0
        self.vma = 0
        self.codeAddr = 0
        self.codeSize = 0
        self.codeId = 0
        self.methodName = None
        self.code = None

    def disCode(self):
        if self.mach == ELF_MACH_ARM:
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif self.mach == ELF_MACH_ARM64:
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        elif self.mach == ELF_MACH_IA32:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif self.mach == ELF_MACH_X64:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            logging.warning('unable to disassemble code 0x%x' % self.mach)
            return self.code
        dump = list()
        for insn in md.disasm(self.code, 0):
            dump.append('0x%x:\t%s\t%s\t%s' % (insn.address, to_hex2(insn.bytes[::-1]), insn.mnemonic, insn.op_str))
        return '\n  '.join(dump)

    def dump(self):
        return '%s\n  code addr=0x%x\n  code size=%d\n  %s' % (self.methodName,
                                                               self.codeAddr,
                                                               self.codeSize,
                                                               self.disCode())

    @staticmethod
    def parseJitMethod(file, elfMachCode):
        jm = JitMethod(elfMachCode)
        jm.event = int.from_bytes(file.read(4), 'little')
        jm.size = int.from_bytes(file.read(4), 'little')
        jm.timestamp = int.from_bytes(file.read(8), 'little')
        jm.pid = int.from_bytes(file.read(4), 'little')
        jm.tid = int.from_bytes(file.read(4), 'little')
        jm.vma = int.from_bytes(file.read(8), 'little')
        jm.codeAddr = int.from_bytes(file.read(8), 'little')
        jm.codeSize = int.from_bytes(file.read(8), 'little')
        jm.codeId = int.from_bytes(file.read(8), 'little')

        spos = file.tell()
        length = 0
        while True:
            if file.read(1) == b'\x00':
                break
            length += 1
        file.seek(spos)
        jm.methodName = file.read(length).decode('utf8')
        file.read(1)  # 0x00 after method name

        jm.code = file.read(jm.codeSize)
        return jm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--in", required=True, help="art jit binary dump data")
    ap.add_argument("-o", "--out", required=True, help="output file name")
    args = vars(ap.parse_args())

    with open(args['in'], 'rb') as inFile:
        # parse magic and version
        magic = inFile.read(4)
        version = int.from_bytes(inFile.read(4), 'little')
        if magic != JIT_MAGIC or version != JIT_VERSION:
            logging.warning('unrecognized magic & version: %s:%d' % (magic, version))
            return
        # parse elf target architecture
        inFile.read(4)
        elfMachCode = int.from_bytes(inFile.read(4), 'little')
        logging.info('target file machine code 0x%x' % elfMachCode)

        # skip jit header
        inFile.seek(40)

        jitMethods = list()
        while True:
            test = inFile.read(1)
            if test == b'':
                break
            inFile.seek(-1, os.SEEK_CUR)
            jitMethods.append(JitMethod.parseJitMethod(inFile, elfMachCode))

        # write result file
        with open(args['out'], 'w') as outFile:
            for jm in jitMethods:
                outFile.write(jm.dump())
                outFile.write('\n\n')


if __name__ == '__main__':
    main()
