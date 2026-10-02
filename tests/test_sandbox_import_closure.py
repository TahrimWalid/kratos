"""The evo-loop sandbox only has SANDBOX_PIP_PACKAGES installed (no network,
by design). A candidate imports kratos.agent.tools there, so that import must
work with nothing else -- otherwise every /evolve test fails with an import
error on a fresh machine (it did: kratos_config gained a python-dotenv import
the image didn't have). Simulated here by refusing every top-level import that
is neither stdlib, Kratos, nor one of those packages (or their own deps)."""
from __future__ import annotations

import subprocess
import sys

from kratos.agent import self_test

# Import names of SANDBOX_PIP_PACKAGES plus what they pull in themselves.
_IMPORT_NAMES = {"pytest": {"pytest", "_pytest", "pluggy", "iniconfig", "packaging", "exceptiongroup",
                            "pygments"},
                 "requests": {"requests", "urllib3", "idna", "certifi", "charset_normalizer", "chardet"},
                 "python-dotenv": {"dotenv"},
                 "tomli": {"tomli"},
                 "rich": {"rich", "markdown_it", "mdurl"}}


def test_the_tool_layer_imports_with_only_the_sandbox_packages():
    assert set(self_test.SANDBOX_PIP_PACKAGES) == set(_IMPORT_NAMES), \
        "update _IMPORT_NAMES (and bump SANDBOX_IMAGE_ALIAS) when the sandbox packages change"
    allowed = sorted(set().union(*_IMPORT_NAMES.values()) | {"kratos"})
    code = f"""
import sys
ALLOWED = set({allowed!r}) | set(sys.stdlib_module_names)
class Block:
    def find_spec(self, name, path=None, target=None):
        if name.split('.')[0] not in ALLOWED:
            raise ImportError(f"not available in the evo-loop sandbox: {{name}}")
        return None
sys.meta_path.insert(0, Block())
import kratos.agent.tools as t
print(len(t.TOOL_REGISTRY))
"""
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    assert int(out.stdout.strip()) >= 10
