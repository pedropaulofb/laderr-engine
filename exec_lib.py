import sys

from laderr_engine.laderr_lib import Laderr

try:
    Laderr.process_specification(
        input_spec_path="C:\\Users\\PedroPauloFavatoBarc\\Dev\\laderr-engine\\laderr-engine\\example\\example_doc_in.toml",
        output_file_base="C:\\Users\\PedroPauloFavatoBarc\\Dev\\laderr-engine\\laderr-engine\\example\\output_lib\\example_doc_out"
    )
except Exception as e:
    print(f"Error processing LaDeRR specification: {e}")
    sys.exit(1)