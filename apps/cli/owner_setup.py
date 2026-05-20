import argparse
import os
import sys

# Make project root importable regardless of CWD
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from core.secure_search import build_index_from_csv, save_index_artifacts


def main() -> None:
    parser = argparse.ArgumentParser(description="Build authenticated encrypted index artifacts.")
    parser.add_argument("--config", default=os.path.join(PROJ_ROOT, "conFig.ini"), help="path to conFig.ini")
    parser.add_argument("--csv", default=os.path.join(PROJ_ROOT, "us-colleges-and-universities.csv"), help="dataset CSV path")
    parser.add_argument("--out", default=THIS_DIR, help="output directory for aui.pkl and K.pkl")
    args = parser.parse_args()

    aui, keys = build_index_from_csv(args.csv, args.config)
    aui_path, key_path = save_index_artifacts(aui, keys, args.out)
    print(f"[owner_setup] Wrote {aui_path} and {key_path}")


if __name__ == "__main__":
    main()
