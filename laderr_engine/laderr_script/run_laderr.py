import argparse

from laderr_engine.laderr_lib import Laderr


def main():
    parser = argparse.ArgumentParser(description="Process a LaDeRR specification file.")

    parser.add_argument("input_spec", help="Path to the input LaDeRR specification file.")
    parser.add_argument("output_spec", help="Path where the processed specification should be saved.")

    parser.add_argument("-v", "--validate", action="store_true", help="Enable validation after reasoning.")
    parser.add_argument("-v0", "--validate-pre", action="store_true", help="Enable validation before reasoning.")
    parser.add_argument("-r", "--reasoning", action="store_true", help="Enable reasoning execution.")
    parser.add_argument("-g", "--save-graph", action="store_true", help="Save the processed graph.")
    parser.add_argument("-g0", "--save-graph-pre", action="store_true", help="Save the graph before processing.")
    parser.add_argument("-i", "--save-visualization", action="store_true", help="Save the processed visualization.")
    parser.add_argument("-i0", "--save-visualization-pre", action="store_true",
                        help="Save the visualization before processing.")
    parser.add_argument("-s", "--silent", action="store_false", help="Disable verbose logging.")

    args = parser.parse_args()

    Laderr.process_specification(
        input_spec_path=args.input_spec,
        output_file_path=args.output_spec,
        validate_pre=args.validate_pre,
        validate_post=args.validate,
        exec_inferences=args.reasoning,
        save_graph_pre=args.save_graph_pre,
        save_graph_post=args.save_graph,
        save_visualization_pre=args.save_visualization_pre,
        save_visualization_post=args.save_visualization,
        verbose=args.silent
    )


if __name__ == "__main__":
    main()
