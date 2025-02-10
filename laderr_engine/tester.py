from icecream import ic
from networkx.generators.classic import ladder_graph
from owlrl import DeductiveClosure, RDFS_OWLRL_Semantics, RDFS_Semantics

from laderr_engine.laderr_lib.handlers.visualization import VisualizationHandler
from laderr_engine.laderr_lib.laderr import Laderr

from owlrl import DeductiveClosure, RDFS_Semantics
from rdflib import Graph, RDF, RDFS, OWL
from icecream import ic  # Debugging


def apply_reasoning_and_clean(graph: Graph) -> Graph:
    """
    Applies OWL reasoning using DeductiveClosure but removes schema-based pollution.

    :param graph: Input RDF graph.
    :return: Cleaned RDF graph with only inferred data.
    """
    # Make a copy of the graph to prevent modifying the original
    reasoned_graph = Graph()
    reasoned_graph += graph

    ic(11, len(reasoned_graph))  # Debugging: Number of triples before reasoning

    # Apply OWL reasoning
    DeductiveClosure(RDFS_OWLRL_Semantics).expand(reasoned_graph)

    ic(21, len(reasoned_graph))  # Debugging: Number of triples after reasoning

    # Create a new graph to store only data-related triples
    cleaned_graph = Graph()

    # Filter out RDFS/OWL pollution
    for subj, pred, obj in reasoned_graph:
        # Exclude RDF(S) / OWL classes from the results
        if subj.startswith("http://www.w3.org/") or obj.startswith("http://www.w3.org/"):
            continue
        if subj in {RDFS.Class, RDFS.Resource, OWL.Class} or obj in {RDFS.Class, RDFS.Resource, OWL.Class}:
            continue
        if pred in {RDF.type} and obj in {RDFS.Class, RDFS.Resource, OWL.Class}:
            continue

        # Keep only data-related triples
        cleaned_graph.add((subj, pred, obj))

    ic(31, len(cleaned_graph))  # Debugging: Number of triples after cleaning

    return cleaned_graph


if __name__ == "__main__":
    # Load spec_metadata_dict and data from the specification
    laderr_file = "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\input_spec2.toml"

    # laderr_graph = Laderr.load_spec_to_laderr_graph(laderr_file)
    # Laderr.validate_laderr_graph(laderr_graph)

    laderr_graph = Laderr.load_spec_to_laderr_graph(laderr_file)

    # ic(1, len(laderr_graph))
    # Apply OWL reasoning using DeductiveClosure
    # apply_reasoning_and_clean(laderr_graph)
    # ic(2, len(laderr_graph))

    Laderr.save_laderr_graph(laderr_graph,
                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph.ttl")
    Laderr.save_laderr_spec_from_graph(laderr_graph,
                                       "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_spec.toml")
    # VisualizationHandler.create_graph_visualization(laderr_graph, "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph.png")
