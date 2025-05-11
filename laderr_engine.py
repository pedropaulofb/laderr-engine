import sys

from laderr_engine.laderr_lib import Laderr

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCE_DIR = os.path.join(BASE_DIR, "..", "..", "resources")

def main():
    if len(sys.argv) != 3:
        print("Usage: python laderr_engine <input_file> <output_base>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_path = sys.argv[2]

    try:
        Laderr.process_specification(
            input_spec_path=input_file,
            output_file_base=output_path
        )
    except Exception as e:
        print(f"Error processing LaDeRR specification: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


