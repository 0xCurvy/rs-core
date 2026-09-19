"""Tiny, deterministic test artifacts; never use the generated setup in production."""
import hashlib
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def u32(n):
    return struct.pack('<I', n)

def u64(n):
    return struct.pack('<Q', n)

def section(number, data):
    return u32(number) + u64(len(data)) + data

def graph(r1cs_digest=bytes(32)):
    result = b'CVYWIT01' + struct.pack('<HHI', 1, 1, 64) + r1cs_digest
    result += struct.pack('<IIII', 4, 4, 2, 3)
    result += b''.join(b'\0' + u32(i) for i in range(3))
    result += bytes([2, 0]) + u32(1) + u32(2)
    result += b''.join(u32(i) for i in [0, 3, 1, 2])
    for name, signal in [('a', 1), ('b', 2)]:
        hash_value = 0xCBF29CE484222325
        for byte in name.encode():
            hash_value = ((hash_value ^ byte) * 0x100000001B3) % 2**64
        result += u64(hash_value) + u32(signal) + u32(1)
    return result

def wtns(values=(1, 33, 3, 11)):
    header = u32(32) + FIELD.to_bytes(32, 'little') + u32(len(values))
    values = b''.join(n.to_bytes(32, 'little') for n in values)
    return b'wtns' + u32(2) + u32(2) + section(1, header) + section(2, values)

def r1cs():
    header = u32(32) + FIELD.to_bytes(32, 'little') + struct.pack('<IIIIQI', 4, 1, 0, 2, 4, 1)
    constraint = b''.join(u32(1) + u32(signal) + (1).to_bytes(32, 'little') for signal in [2, 3, 1])
    labels = b''.join(u64(i) for i in range(4))
    return b'r1cs' + u32(1) + u32(3) + section(1, header) + section(2, constraint) + section(3, labels)

def write(directory):
    directory = pathlib.Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    circuit = r1cs()
    for name, data in {'circuit.r1cs': circuit, 'graph.bin': graph(hashlib.sha256(circuit).digest()),
                       'witness.wtns': wtns(), 'input.json': b'{"a":"3","b":"11"}',
                       'key.zkey': (ROOT / 'crates/prover/testdata/multiplier.zkey').read_bytes(),
                       'vk.json': (ROOT / 'crates/prover/testdata/multiplier.vk.json').read_bytes()}.items():
        (directory / name).write_bytes(data)
    return directory

if __name__ == '__main__':
    import sys
    write(sys.argv[1])
