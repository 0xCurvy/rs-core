#!/usr/bin/env python3
"""Validate a private artifact snapshot and emit a reviewable local release bundle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

NAMES = {'zkey': 'key.zkey', 'graph': 'graph.bin', 'wtns': 'witness.wtns',
         'vk': 'vk.json', 'r1cs': 'circuit.r1cs', 'ptau': 'ceremony.ptau', 'input': 'input.json'}
LIMITS = dict(zkey=4*1024**3, graph=96*1024**2, wtns=256*1024**2 + 512,
              vk=16*1024**2, r1cs=16*1024**3, ptau=32*1024**3, input=16*1024**2)

def digest(path):
    hasher = hashlib.sha256()
    size = 0
    with path.open('rb') as source:
        while block := source.read(1024**2):
            hasher.update(block)
            size += len(block)
    return {'bytes': size, 'sha256': hasher.hexdigest()}

def snapshot(source, destination, limit):
    with open(source, 'rb') as reader, destination.open('xb') as writer:
        metadata = os.fstat(reader.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError(f'{source}: expected a regular file of at most {limit} bytes')
        remaining = limit
        while block := reader.read(min(1024**2, remaining + 1)):
            remaining -= len(block)
            if remaining < 0:
                raise ValueError(f'{source}: file grew beyond its size limit')
            writer.write(block)
    destination.chmod(0o400)

def validate(args):
    output = Path(args.output).resolve()
    if output.exists():
        raise ValueError('output already exists; choose a new release bundle directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.curvy-release-', dir=output.parent))
    try:
        for key, name in NAMES.items():
            snapshot(getattr(args, key), stage / name, LIMITS[key])
        pins = {key: digest(stage / name) for key, name in NAMES.items()}
        # The ceremony pin must come from an independently reviewed trust root.
        if pins['ptau']['sha256'] != args.ptau_sha256.lower():
            raise ValueError('PTAU digest does not match the trusted ceremony pin')
        commands = [
            [args.snarkjs, 'powersoftau', 'verify', str(stage / NAMES['ptau'])],
            [args.snarkjs, 'zkey', 'verify', str(stage / NAMES['r1cs']), str(stage / NAMES['ptau']), str(stage / NAMES['zkey'])],
            [args.snarkjs, 'wtns', 'check', str(stage / NAMES['r1cs']), str(stage / NAMES['wtns'])],
            [args.validator, *[str(stage / NAMES[key]) for key in ['zkey', 'graph', 'wtns', 'vk', 'r1cs', 'input']]],
        ]
        for i, command in enumerate(commands):
            result = subprocess.run(command, text=True, capture_output=True, timeout=args.timeout)
            (stage / f'check-{i}.log').write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(f'release check {i} failed (exit {result.returncode}):\n{(result.stdout + result.stderr)[-2048:]}')
        report = json.loads(result.stdout)
        for check in ['compatibilityChecks', 'fullPointValidation', 'crsConsistency',
                      'verificationKeyEquality', 'witnessReference', 'sageWitnessReference']:
            if report.get(check) != 'passed':
                raise ValueError(f'required release check did not pass: {check}; build validator with --features sage')
        aliases = {'vk': 'verificationKey', 'wtns': 'wtnsFixture', 'input': 'inputFixture'}
        for key, pin in pins.items():
            if digest(stage / NAMES[key]) != pin:
                raise ValueError(f'staged artifact changed during validation: {key}')
            if key != 'ptau':
                actual = report[aliases.get(key, key)]
                if any(actual.get(field) != value for field, value in pin.items()):
                    raise ValueError(f'validator observed different bytes: {key}')
        report['ceremony'] = pins['ptau']
        report['ceremonyTranscriptVerification'] = 'passed'
        report['zkeyR1csPtauVerification'] = 'passed'
        report['r1csWitnessCheck'] = 'passed'
        (stage / 'release-manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        # Reserve the destination without overwriting another release.
        output.mkdir()
        try:
            for path in stage.iterdir():
                path.rename(output / path.name)
        except BaseException:
            shutil.rmtree(output)
            raise
        print(output / 'release-manifest.json')
    finally:
        shutil.rmtree(stage)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in NAMES:
        parser.add_argument('--' + key, required=True)
    parser.add_argument('--ptau-sha256', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--snarkjs', default=str(Path(__file__).resolve().parent / 'node_modules/.bin/snarkjs'))
    parser.add_argument('--validator', default='target/release/examples/artifact_manifest_check')
    parser.add_argument('--timeout', type=int, default=3600)
    validate(parser.parse_args())
