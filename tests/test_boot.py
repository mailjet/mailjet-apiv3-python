import cProfile
import pstats
import sys
from pathlib import Path

# Add project root to sys.path to import local mailjet_rest
sys.path.insert(0, str(Path(__file__).parent.parent))

def boot_test() -> None:
    """ Profile the cost of initial module imports and client instantiation. """
    # Importing inside the function ensures we capture the disk-crawling overhead
    from mailjet_rest.client import Client
    Client(auth=("api_key", "api_secret"))

if __name__ == "__main__":
    profiler = cProfile.Profile()
    profiler.enable()
    boot_test()
    profiler.disable()

    # Sort results by 'tottime' (Total internal time) to find the biggest offenders
    stats = pstats.Stats(profiler).sort_stats('tottime')

    print("\n--- TOP 20 TIME-CONSUMING OPERATIONS (Cold Boot) ---")
    stats.print_stats(20)
