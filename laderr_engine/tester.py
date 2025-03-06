from graphviz import Graph
from rdflib import RDF

from laderr_engine.laderr_lib.constants import LADERR_NS
from laderr_engine.laderr_lib.laderr import Laderr
from laderr_engine.laderr_lib.services.visualization import GraphCreator

def replace_scenario(graph: Graph, new_scenario: str):
    # Assume there's exactly one LaderrSpecification instance
    for spec in graph.subjects(RDF.type, LADERR_NS.LaderrSpecification):
        # Remove current scenario
        graph.remove((spec, LADERR_NS.scenario, None))
        # Add new scenario
        scenario_uri = LADERR_NS[new_scenario.lower()]
        graph.add((spec, LADERR_NS.scenario, scenario_uri))
        print(f"Scenario replaced with '{new_scenario.upper()}'.")
        break
    else:
        print("No LaderrSpecification found.")

if __name__ == "__main__":
    # Load spec_metadata_dict and data from the specification
    laderr_file = "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\example.toml"

    laderr_graph = Laderr.load_spec_to_laderr_graph(laderr_file)

    GraphCreator.create_graph_visualization(laderr_graph,
                                            "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph1.png")

    Laderr.save_laderr_graph(laderr_graph,
                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph1.ttl")

    exit(0)

    laderr_graph = Laderr.exec_inferences_ladder_graph(laderr_graph)

    replace_scenario(laderr_graph, 'incident')  # replace with 'operational', 'resilient', etc. as needed

    Laderr.save_laderr_graph(laderr_graph,
                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph2.ttl")
    Laderr.save_laderr_spec_from_graph(laderr_graph,
                                       "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_spec.toml")

    GraphCreator.create_graph_visualization(laderr_graph,
                                            "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph2.png")

# TODO: Do I first execute assign the default values or execute SHACL? If former, then no need for some properties.


