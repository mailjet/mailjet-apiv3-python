"""Performance and boot speed profiling tests for the Mailjet SDK."""

import subprocess
import sys
import time
from pathlib import Path


class TestBootPerformance:
    """Class to profile SDK cold-boot initialization and import overhead."""

    def test_client_boot_profile(self) -> None:
        """Profile the SDK boot time.

        Placing the import INSIDE the profiled function ensures we capture
        the exact cost of Python crawling the disk to compile the modules
        (assuming this test runs in an isolated worker or as a script).
        """
        # Inject the project root into sys.path inside the generated script
        project_root = str(Path(__file__).parent.parent)

        profiler_script = f"""
import sys
sys.path.insert(0, "{project_root}")

import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

from mailjet_rest.client import Client
try:
    from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
except ImportError:
    pass  # Graceful degradation for older baseline tags

_client = Client(auth=("api", "key"))

profiler.disable()

stats = pstats.Stats(profiler).sort_stats("tottime")

print("\\n--- TOP 20 TIME-CONSUMING OPERATIONS (Cold Boot) ---")
stats.print_stats(20)
"""

        start_time = time.perf_counter()

        # Execute the script in a sterile subprocess to bypass pytest's sys.modules cache
        result = subprocess.run(
            [sys.executable, "-c", profiler_script],
            capture_output=True,
            text=True,
            check=True,
        )

        end_time = time.perf_counter()

        # Output the exact cProfile stats to the Pytest console
        print(result.stdout)

        total_wall_clock = end_time - start_time
        print(f"\033[1;32mTotal Subprocess Wall-Clock Time: {total_wall_clock:.4f}s\033[0m")

        # Guardrail to ensure the boot process stays within expected performance bounds
        assert total_wall_clock < 1.5, "Cold boot exceeded 1.5 second threshold!"


if __name__ == "__main__":
    test_instance = TestBootPerformance()
    test_instance.test_client_boot_profile()
