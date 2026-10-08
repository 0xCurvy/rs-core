"""Exercise every release gate using a fresh, deliberately insecure test ceremony."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from fixtures import write, wtns
from validate_release import validate

SNARKJS = Path(__file__).resolve().parent / 'node_modules/.bin/snarkjs'
VALIDATOR = Path(os.environ.get('CURVY_ARTIFACT_VALIDATOR', 'target/debug/examples/artifact_manifest_check')).resolve()

class PipelineTests(unittest.TestCase):
    def test_real_transcript_r1cs_and_witness_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(directory)
            def run(*args):
                result = subprocess.run([str(SNARKJS), *map(str,args)], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run('powersoftau', 'new', 'bn128', 4, root/'phase1.ptau')
            run('powersoftau', 'contribute', root/'phase1.ptau', root/'contributed.ptau', '-e=PUBLIC TEST ENTROPY - NEVER PRODUCTION')
            run('powersoftau', 'prepare', 'phase2', root/'contributed.ptau', root/'ceremony.ptau')
            run('groth16', 'setup', root/'circuit.r1cs', root/'ceremony.ptau', root/'fresh.zkey')
            run('zkey', 'export', 'verificationkey', root/'fresh.zkey', root/'fresh.vk.json')
            files = dict(zkey='fresh.zkey', graph='graph.bin', wtns='witness.wtns', vk='fresh.vk.json',
                         r1cs='circuit.r1cs', ptau='ceremony.ptau', input='input.json')
            args = SimpleNamespace(**{key:str(root/name) for key,name in files.items()}, output=str(root/'valid'),
                    ptau_sha256=hashlib.sha256((root/'ceremony.ptau').read_bytes()).hexdigest(), snarkjs=str(SNARKJS), validator=str(VALIDATOR), timeout=60)
            validate(args)
            self.assertTrue((root/'valid/release-manifest.json').is_file())
            args.output = str(root/'invalid-witness')
            (root/'witness.wtns').write_bytes(wtns((1,33,4,11)))
            with self.assertRaisesRegex(RuntimeError, 'release check 2 failed'):
                validate(args)
            self.assertFalse(Path(args.output).exists())
            args.ptau_sha256 = '00' * 32
            with self.assertRaisesRegex(ValueError, 'trusted ceremony pin'):
                validate(args)
            self.assertFalse(Path(args.output).exists())
            self.assertEqual(list(root.glob('.curvy-release-*')), [])

if __name__ == '__main__':
    unittest.main()
