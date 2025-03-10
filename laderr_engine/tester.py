from graphviz import Graph
from loguru import logger
from rdflib import RDF

from laderr_engine.laderr_lib.constants import LADERR_NS
from laderr_engine.laderr_lib.laderr import Laderr
from laderr_engine.laderr_lib.services.specification import SpecificationHandler
from laderr_engine.laderr_lib.services.validation import ValidationHandler
from laderr_engine.laderr_lib.services.visualization import GraphCreator


def replace_scenario(graph: Graph, new_scenario: str):
    # Assume there's exactly one LaderrSpecification instance
    for spec in graph.subjects(RDF.type, LADERR_NS.LaderrSpecification):
        # Remove current scenario
        graph.remove((spec, LADERR_NS.scenario, None))
        # Add new scenario
        scenario_uri = LADERR_NS[new_scenario.lower()]
        graph.add((spec, LADERR_NS.scenario, scenario_uri))
        logger.info(f"Scenario replaced with '{new_scenario.upper()}'.")
        break
    else:
        logger.warning("No LaderrSpecification found.")


if __name__ == "__main__":
    # Load spec_metadata_dict and data from the specification
    laderr_file = "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\in_spec.toml"

    laderr_graph = Laderr.load_spec_to_laderr_graph(laderr_file)

    GraphCreator.create_graph_visualization(laderr_graph,
                                            "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph1.png")

    Laderr.save_laderr_graph(laderr_graph,
                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph1.ttl")

    SpecificationHandler.write_specification(laderr_graph,
                                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\out_spec1.toml")

    laderr_graph = Laderr.exec_inferences_ladder_graph(laderr_graph)

    ValidationHandler.validate_laderr_graph(laderr_graph)

    Laderr.save_laderr_graph(laderr_graph,
                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph2.ttl")
    Laderr.save_laderr_spec_from_graph(laderr_graph,
                                       "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_spec.toml")

    GraphCreator.create_graph_visualization(laderr_graph,
                                            "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph2.png")

    SpecificationHandler.write_specification(laderr_graph,
                                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\out_spec2.toml")
