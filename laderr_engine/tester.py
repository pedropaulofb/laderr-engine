from laderr_engine.laderr_lib.laderr import Laderr
from laderr_engine.laderr_lib.services.visualization import GraphCreator

if __name__ == "__main__":
    # Load spec_metadata_dict and data from the specification
    laderr_file = "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\example.toml"

    # laderr_graph = Laderr.load_spec_to_laderr_graph(laderr_file)
    # Laderr.validate_laderr_graph(laderr_graph)

    laderr_graph = Laderr.load_spec_to_laderr_graph(laderr_file)

    GraphCreator.create_graph_visualization(laderr_graph,
                                            "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph1.png")

    Laderr.save_laderr_graph(laderr_graph,
                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph1.ttl")

    laderr_graph = Laderr.exec_inferences_ladder_graph(laderr_graph)

    # Add the triple to the graph
    # Define Subject, Predicate, and Object
    # subject = URIRef("https://socio-ecological.example.com/laderr#greenridge_dam")
    # predicate = URIRef(RDF.type)
    # obj = URIRef("https://w3id.org/laderr#Asset")
    # laderr_graph.add((subject, predicate, obj))
    #
    # obj = URIRef("https://w3id.org/laderr#Threat")
    # laderr_graph.add((subject, predicate, obj))
    #
    # subject = URIRef("https://socio-ecological.example.com/laderr#reinforcement_team")
    # obj = URIRef("https://w3id.org/laderr#Threat")
    # laderr_graph.add((subject, predicate, obj))
    #
    # subject = URIRef("https://socio-ecological.example.com/laderr#test")
    # predicate = URIRef(RDF.type)
    # obj = URIRef("https://w3id.org/laderr#Disposition")
    # laderr_graph.add((subject, predicate, obj))
    #
    # subject = URIRef("https://socio-ecological.example.com/laderr#levee_reinforcement")
    # predicate = URIRef(RDF.type)
    # obj = URIRef("https://w3id.org/laderr#Vulnerability")
    # laderr_graph.add((subject, predicate, obj))

    Laderr.save_laderr_graph(laderr_graph,
                             "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph2.ttl")
    Laderr.save_laderr_spec_from_graph(laderr_graph,
                                       "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_spec.toml")

    GraphCreator.create_graph_visualization(laderr_graph,
                                            "C:\\Users\\FavatoBarcelosPP\\Dev\\laderr_engine\\manual_test_resources\\output_graph2.png")
