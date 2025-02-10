from laderr_engine.laderr_lib.laderr import Laderr

if __name__ == "__main__":
    # Load spec_metadata_dict and data from the specification
    laderr_file = "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\input_spec.toml"

    laderr_graph = Laderr.load_spec_to_laderr_graph(laderr_file)
    Laderr.validate_laderr_graph(laderr_graph)
    Laderr.save_laderr_graph(laderr_graph,
                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph.ttl")
    Laderr.save_laderr_spec_from_graph(laderr_graph,
                                       "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_spec.toml")
