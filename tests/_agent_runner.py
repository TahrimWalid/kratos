"""
Standalone subprocess entry point: runs the real ReAct agent loop for one
investigation goal and prints the structured result as JSON.

Used by agent_scenarios.py so each scenario runs in a fresh subprocess --
backend selection (KRATOS_LLM_BACKEND, LLM_BASE_URL/LLM_API_KEY/LLM_MODEL,
etc.) is read once at module-import time in llm_config.py, so switching
backends between scenarios within one long-lived Python/pytest process
would not reliably take effect. A fresh subprocess per scenario re-reads
the environment fresh.

Usage: python _agent_runner.py "<goal>" <data_dir> [max_iters]
"""
import json
import sys
from pathlib import Path

from kratos.agent.loop import run_agent


def main() -> None:
    goal = sys.argv[1]
    data_dir = Path(sys.argv[2])
    max_iters = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    result = run_agent(goal, data_dir, max_iters=max_iters)

    # Marker line lets the caller reliably split real stdout noise (backend
    # selection messages on stderr are separate, but tool handlers like
    # run_nmap_scan print progress to stdout too) from the actual JSON.
    print("===SCENARIO_RESULT_JSON===")
    print(json.dumps(result, default=str))


if __name__ == "__main__":
    main()
