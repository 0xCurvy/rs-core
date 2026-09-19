"""Regressions for release pin/validation consistency (POSIX FIFO synchronization)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from fixtures import write, graph

VALIDATOR = os.environ.get('CURVY_ARTIFACT_VALIDATOR', 'target/debug/examples/artifact_manifest_check')

class ReleaseTests(unittest.TestCase):
    def command(self, root):
        return [VALIDATOR, *[str(root / name) for name in ['key.zkey', 'graph.bin', 'witness.wtns', 'vk.json', 'circuit.r1cs']]]

    def test_pins_refer_to_validated_snapshots_after_source_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(directory)
            pins = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ['key.zkey', 'vk.json']}
            circuit = (root / 'circuit.r1cs').read_bytes()
            (root / 'circuit.r1cs').unlink()
            os.mkfifo(root / 'circuit.r1cs')
            process = subprocess.Popen(self.command(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        writer = os.open(root / 'circuit.r1cs', os.O_WRONLY | os.O_NONBLOCK)
                        break
                    except OSError:
                        if time.monotonic() > deadline or process.poll() is not None:
                            self.fail('validator did not reach the post-validation R1CS read')
                        time.sleep(0.01)
                with os.fdopen(writer, 'wb') as fifo:
                    for name in pins:
                        (root / name).write_bytes(b'invalid replacement')
                    fifo.write(circuit)
                output, error = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, error)
                manifest = json.loads(output)
                self.assertEqual(manifest['zkey']['sha256'], pins['key.zkey'])
                self.assertEqual(manifest['verificationKey']['sha256'], pins['vk.json'])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_witness_reference_compares_every_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(directory)
            command = self.command(root) + [str(root / 'input.json')]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['witnessReference'], 'passed')
            (root / 'input.json').write_text('{"a":"4","b":"11"}')
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('differs from the reference WTNS', result.stderr)

if __name__ == '__main__':
    unittest.main()
