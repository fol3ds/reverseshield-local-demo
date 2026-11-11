"""Optional document-generation tools used only by the test suite."""
import os
import shutil
import subprocess
import sys
import unittest


_DOCX_PROBE = '''\
try:
    import docx
except ModuleNotFoundError as error:
    if error.name != "docx":
        raise
    raise SystemExit(3)
'''


def docx_python():
    """Prefer this interpreter; discover existing POSIX document tooling."""
    candidates = [sys.executable]
    if sys.platform != 'win32':
        for search_path in (None, os.defpath):
            for name in ('python3', 'python'):
                candidate = shutil.which(name, path=search_path)
                if candidate:
                    candidates.append(candidate)
    for candidate in dict.fromkeys(candidates):
        result = subprocess.run([candidate, '-c', _DOCX_PROBE], capture_output=True,
                                text=True, timeout=15)
        if result.returncode == 0:
            return candidate
        if result.returncode != 3:  # Only the explicitly missing docx import may skip.
            result.check_returncode()
    raise unittest.SkipTest(
        'optional python-docx is not installed in the available interpreter(s); '
        'install requirements-docs.txt to run document-generation tests')
