"""Minimal fixed entry point used by Phase 5F-C Test A."""
import os

OUTPUT_PATH = r"D:\Lumi\workspace\phase5fc_minimal.txt"


def main():
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write("USERNAME=" + os.environ.get("USERNAME", "") + "\n")
        f.write("PID=" + str(os.getpid()) + "\n")


if __name__ == "__main__":
    main()
