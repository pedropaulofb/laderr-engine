from laderr_engine.laderr_lib import Laderr

test_num = "P"

Laderr.process_specification(f"examples/example_doc_{test_num}_in.toml",
                             f"examples/example_doc_{test_num}/example_doc_{test_num}_out")