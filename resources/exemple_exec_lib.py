import sys

from laderr_engine.laderr_lib import Laderr

try:
    Laderr.process_specification(
        input_spec_path="C:\\Users\\PedroPauloFavatoBarc\\Dev\\laderr-engine\\example\\edoc_examples\\example_scenario_resilient.toml",
        output_file_base="C:\\Users\\PedroPauloFavatoBarc\\Dev\\laderr-engine\\example\\edoc_examples\\output_scenario_resilient\\out_scenario_resilient",
    )
except Exception as e:
    print(f"Error processing LaDeRR specification: {e}")
    sys.exit(1)