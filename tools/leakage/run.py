#!/usr/bin/env python3
"""Build release leakage probes and retain measurements with build provenance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
CASES = ['control', 'base_mul', 'reduce_wide', 'nonce_candidate', 'response',
         'sign_seed', 'sign_scalar', 'blake512', 'poseidon_secret', 'decimal',
         'owner_hash_decimal', 'poseidon_vartime']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['dudect', 'timecop', 'phases'])
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--samples', type=int, default=200000)
    parser.add_argument('--cases', nargs='+', choices=CASES, default=CASES[:-1])
    parser.add_argument('--family', choices=['fixed-random', 'sparse-dense', 'both'], default='both')
    parser.add_argument('--allow-variable-time', nargs='*', choices=['poseidon_vartime', 'sign_scalar'], default=[])
    args = parser.parse_args()
    if not 30000 <= args.samples <= 100000000:
        parser.error('samples must be between 30000 and 100000000')
    if args.mode == 'phases':
        args.cases = [case for case in args.cases if case in ['sign_seed', 'sign_scalar']]
        if not args.cases:
            parser.error('phases requires at least one signing case')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'validation.json').exists():
        parser.error('output already contains a validation report; use a fresh directory')
    env = dict(os.environ, CARGO_PROFILE_RELEASE_DEBUG='1')
    target = Path(env.get('CARGO_TARGET_DIR', ROOT / 'target')).resolve()
    build = ['cargo', 'build', '--locked', '--release', '-p', 'curvy-leakage']
    binary = out / args.mode
    link = [*shlex.split(env.get('CC', 'cc')), '-O3', '-g', str(ROOT / f'tools/leakage/{args.mode}.c'),
            str(target / 'release/libcurvy_leakage.a'), '-lpthread', '-ldl', '-lm', '-o', str(binary)]
    with (out / 'build.log').open('w') as log:
        subprocess.run(build, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        subprocess.run(link, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    cpu = platform.processor()
    if sys.platform == 'darwin':
        cpu = subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True).strip()
    elif Path('/proc/cpuinfo').exists():
        cpu = Path('/proc/cpuinfo').read_text()
    report = {
        'mode': args.mode, 'platform': platform.platform(), 'machine': platform.machine(), 'cpu': cpu,
        'rustc': subprocess.check_output(['rustc', '-Vv'], text=True),
        'compiler': subprocess.check_output([link[0], '--version'], text=True),
        'build_commands': [build, link], 'release_debug': '1',
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'source_sha256': {}, 'results': [], 'allowed_variable_time_cases': args.allow_variable_time,
    }
    for relative in ['Cargo.toml', 'Cargo.lock', 'crates/core/Cargo.toml']:
        report['source_sha256'][relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    for path in sorted((ROOT / 'crates/core/src').rglob('*.rs')):
        report['source_sha256'][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted((ROOT / 'tools/leakage').rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            report['source_sha256'][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if args.mode == 'timecop':
        report['valgrind'] = subprocess.check_output(['valgrind', '--version'], text=True).strip()
    cases = args.cases if args.mode == 'phases' else ['control'] + [case for case in args.cases if case != 'control']
    families = ['fixed-random', 'sparse-dense'] if args.family == 'both' else [args.family]
    failed = False
    for case in cases:
        for family in families if args.mode != 'timecop' else ['taint']:
            stem = f'{case}-{family}'
            command = [str(binary), case, family, str(args.samples)] if args.mode != 'timecop' else [
                'valgrind', '--tool=memcheck', '--track-origins=yes', '--error-exitcode=99',
                '--xml=yes', f'--xml-file={out / (stem + ".xml")}',
                '--errors-for-leak-kinds=none', '--leak-check=no', '--error-limit=no', str(binary), case]
            start = time.monotonic()
            with (out / f'{stem}.log').open('w') as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
            if args.mode != 'timecop':
                lines = (out / f'{stem}.log').read_text().splitlines()
                matches = [line[7:] for line in lines if line.startswith('RESULT ')]
                item = json.loads(matches[-1]) if matches else {'case': case, 'family': family, 'status': 'tool_failed'}
                detected = item['status'] == 'leakage_detected'
                valid_statuses = ['profiled'] if args.mode == 'phases' else ['leakage_detected', 'no_leakage_detected']
                valid = result.returncode == 0 and item['status'] in valid_statuses
            else:
                xml = out / f'{stem}.xml'
                try:
                    errors = ET.parse(xml).getroot().findall('error')
                    kinds = [error.findtext('kind') for error in errors]
                    detected = any(kind in ['UninitCondition', 'UninitValue'] for kind in kinds)
                    valid = result.returncode == (99 if errors else 0) and all(kind in ['UninitCondition', 'UninitValue'] for kind in kinds)
                    if case == 'control':
                        valid &= any('mul_point_escalar' in (frame.text or '') for error in errors for frame in error.findall('.//fn'))
                except (ET.ParseError, FileNotFoundError):
                    kinds, detected, valid = [], False, False
                item = {'case': case, 'status': 'tool_failed' if not valid else 'taint_detected' if detected else 'no_taint_detected',
                        'error_kinds': kinds, 'xml': xml.name}
            item.update(command=command, exit_code=result.returncode, seconds=time.monotonic()-start, log=f'{stem}.log')
            report['results'].append(item)
            failed |= not valid or (not detected if case == 'control' else detected and case not in args.allow_variable_time)
            (out / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
            print(stem, item['status'], flush=True)
            if case == 'control' and (not detected or not valid):
                print('The variable-time control was not detected; assessment is invalid.', file=sys.stderr)
                return 2
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
