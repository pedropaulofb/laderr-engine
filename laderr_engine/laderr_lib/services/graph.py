"""
Module for handling RDF laderr_graph operations in the LaDeRR framework.

This module provides functionalities for loading RDF schemas and saving RDF graphs in various formats.
"""
import os
from collections import defaultdict

from loguru import logger
from rdflib import Graph, RDF, XSD, Literal, RDFS, Namespace, URIRef, BNode, OWL, DCTERMS
from rdflib.exceptions import ParserError

from laderr_engine.laderr_lib.constants import LADERR_SCHEMA_PATH, LADERR_NS
from laderr_engine.laderr_lib.services.specification import SpecificationHandler


class GraphHandler:
    """
    Handles operations related to RDF laderr_graph loading and saving.

    This class provides methods to:
    - Load RDF schemas from a file into an RDFLib laderr_graph.
    - Serialize and save RDF graphs to a file in a specified format.
    """

    @staticmethod
    def _load_laderr_schema() -> Graph:
        """
        Loads an RDF schema file into an RDFLib laderr_graph.

        This method reads an RDF file and parses its contents into an RDFLib laderr_graph, allowing further processing and
        validation of RDF data structures.

        :return: An RDFLib laderr_graph containing the parsed RDF data.
        :rtype: Graph
        :raises FileNotFoundError: If the specified RDF file does not exist.
        :raises ValueError: If the RDF file is malformed or cannot be parsed.
        """
        # Initialize the laderr_graph
        graph = Graph()

        try:
            # Parse the file into the laderr_graph
            graph.parse(LADERR_SCHEMA_PATH)
            logger.info(f"Loaded LaDeRR schema from '{LADERR_SCHEMA_PATH}'.")
        except (ParserError, ValueError) as e:
            raise ValueError(
                f"Failed to parse the RDF file '{LADERR_SCHEMA_PATH}'. Ensure it is a valid RDF file.") from e

        return graph

    @staticmethod
    def save_graph(graph: Graph, file_path: str, format: str = "turtle") -> None:
        """
        Serializes and saves an RDF laderr_graph to a file.

        This method takes an RDF laderr_graph and serializes it into a specified format before writing it to a file.
        The function ensures that the target directory exists before attempting to write the file.

        :param graph: The RDF laderr_graph to be serialized and saved.
        :type graph: Graph
        :param file_path: Path where the serialized RDF laderr_graph will be stored.
        :type file_path: str
        :param format: The serialization format (e.g., "turtle", "xml", "nt", "json-ld"). Default is "turtle".
        :type format: str
        :raises ValueError: If the specified serialization format is not supported.
        :raises OSError: If the file cannot be written due to permission issues or invalid path.
        """
        try:
            # Ensure the output directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Serialize and save the laderr_graph
            graph.serialize(destination=file_path, format=format)
            logger.success(f"Graph saved successfully to '{file_path}' in format '{format}'.")
        except ValueError as e:
            raise ValueError(f"Serialization format '{format}' is not supported.") from e
        except OSError as e:
            raise OSError(f"Could not write to file '{file_path}': {e}") from e

    @staticmethod
    def _initialize_graph_with_namespaces(spec_metadata: dict[str, object]) -> tuple[Graph, Namespace, Namespace]:
        """
        Initializes an RDFLib graph with the appropriate namespaces.

        This method creates an RDF graph and binds the necessary namespaces, ensuring that
        all RDF entities can be correctly referenced.

        :param spec_metadata: Dictionary containing metadata information, including a validated base URI.
        :type spec_metadata: dict[str, object]
        :return: A tuple containing the RDF graph, data namespace, and specification URI.
        :rtype: tuple[Graph, Namespace, Namespace]
        """
        base_uri = spec_metadata.get("baseURI", "https://laderr.laderr#")
        data_ns = Namespace(base_uri)
        graph = Graph()
        graph.bind("", data_ns)  # Bind default namespace
        graph.bind("laderr", LADERR_NS)  # Bind LaDeRR namespace

        # Create the central Specification instance
        specification_uri = data_ns.Specification
        graph.add((specification_uri, RDF.type, LADERR_NS.Specification))
        graph.add((specification_uri, DCTERMS.conformsTo, URIRef("https://w3id.org/laderr")))

        return graph, data_ns, specification_uri

    @staticmethod
    def _process_instance(graph: Graph, data_ns: Namespace, class_type: str, instance_id: str,
                          properties: dict) -> None:
        """
        Adds an instance and its properties to the RDF graph.
        """
        instance_uri = data_ns[instance_id]
        graph.add((instance_uri, RDF.type, LADERR_NS[class_type]))

        uri_props = {"disables", "exploits", "exposes", "capabilities", "vulnerabilities"}

        for prop, value in properties.items():
            if prop in {"id", "scenarios"}:
                continue  # 'id' is already used, 'scenarios' is handled externally

            prop_uri = RDFS.label if prop == "label" else LADERR_NS[prop]

            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        nested_id = item.get("id", BNode())
                        GraphHandler._process_instance(graph, data_ns, prop, nested_id, item)
                        graph.add((instance_uri, prop_uri, data_ns[nested_id]))
                    elif prop in uri_props:
                        graph.add((instance_uri, prop_uri, data_ns[item]))
                    else:
                        graph.add((instance_uri, prop_uri, Literal(item)))
            elif isinstance(value, dict):
                nested_id = value.get("id", BNode())
                GraphHandler._process_instance(graph, data_ns, prop, nested_id, value)
                graph.add((instance_uri, prop_uri, data_ns[nested_id]))
            elif prop == "state":
                state_uri = LADERR_NS.enabled if value.lower() == "enabled" else LADERR_NS.disabled
                graph.add((instance_uri, prop_uri, state_uri))
            elif prop in uri_props:
                graph.add((instance_uri, prop_uri, data_ns[value]))
            else:
                graph.add((instance_uri, prop_uri, Literal(value)))

    @staticmethod
    def _convert_data_to_graph(spec_metadata: dict, spec_data: dict) -> Graph:
        """
        Converts the specification data into an RDFLib Graph.
        """
        graph, data_ns, specification_uri = GraphHandler._initialize_graph_with_namespaces(spec_metadata)

        scenarios = spec_data.get("Scenario", {})
        for scenario_id, scenario_content in scenarios.items():
            scenario_uri = data_ns[scenario_id]
            graph.add((specification_uri, LADERR_NS.constructs, scenario_uri))
            graph.add((scenario_uri, RDF.type, LADERR_NS.Scenario))

            # Add label, situation, and status
            label = scenario_content.get("label")
            if label:
                graph.add((scenario_uri, RDFS.label, Literal(label)))
            situation = scenario_content.get("situation")
            if situation:
                graph.add((scenario_uri, LADERR_NS.situation, LADERR_NS[situation]))
            status = scenario_content.get("status")
            if status:
                graph.add((scenario_uri, LADERR_NS.status, LADERR_NS[status]))

        # Now process constructs in each scenario key: "s1", "s2", ...
        for scenario_id, scenario_block in spec_data.items():
            if scenario_id in {"Scenario", "Entity", "Capability", "Vulnerability"}:
                continue  # Skip global blocks

            scenario_uri = data_ns[scenario_id]
            if not isinstance(scenario_block, dict):
                continue

            for class_type, instances in scenario_block.items():
                if not isinstance(instances, dict):
                    continue
                for instance_id, properties in instances.items():
                    if not isinstance(properties, dict):
                        continue

                    GraphHandler._process_instance(graph, data_ns, class_type, instance_id, properties)

                    instance_uri = data_ns[instance_id]
                    graph.add((specification_uri, LADERR_NS.constructs, instance_uri))
                    graph.add((scenario_uri, LADERR_NS.components, instance_uri))

        # Process global constructs (those outside scenarios), like Entity definitions
        for class_type in {"Entity", "Capability", "Vulnerability"}:
            class_block = spec_data.get(class_type, {})
            for instance_id, instance_data in class_block.items():
                if not isinstance(instance_data, dict) or instance_id in {"id", "label"}:
                    continue

                GraphHandler._process_instance(graph, data_ns, class_type, instance_id, instance_data)
                instance_uri = data_ns[instance_id]
                graph.add((specification_uri, LADERR_NS.constructs, instance_uri))

                # Link to scenarios based on instance_data["scenarios"]
                for scenario_id in instance_data.get("scenarios", []):
                    scenario_uri = data_ns[scenario_id]
                    graph.add((scenario_uri, LADERR_NS.components, instance_uri))

        return graph

    @staticmethod
    def _convert_metadata_to_graph(metadata: dict[str, object], spec_data: dict[str, dict[str, object]]) -> tuple[
        Graph, Namespace]:
        expected_datatypes = {
            "baseURI": XSD.anyURI,
            "createdBy": XSD.string,
            "createdOn": XSD.dateTime,
            "modifiedOn": XSD.dateTime,
            "title": XSD.string,
            "description": XSD.string,
            "version": XSD.string,
        }

        base_uri = metadata.get("baseURI", "https://laderr.laderr#")
        data_ns = Namespace(base_uri)
        graph = Graph()
        graph.bind("", data_ns)
        graph.bind("laderr", LADERR_NS)

        specification = data_ns.Specification
        graph.add((specification, RDF.type, LADERR_NS.Specification))
        graph.add((specification, DCTERMS.conformsTo, URIRef("https://w3id.org/laderr")))

        for key, value in metadata.items():
            if key not in expected_datatypes:
                continue
            datatype = expected_datatypes[key]
            prop_uri = LADERR_NS[key]
            if isinstance(value, list):
                for item in value:
                    graph.add((specification, prop_uri, Literal(item, datatype=datatype)))
            else:
                graph.add((specification, prop_uri, Literal(value, datatype=datatype)))

        graph.add((specification, LADERR_NS.baseURI, Literal(base_uri, datatype=XSD.anyURI)))

        for scenario_id, scenario_data in spec_data.get("Scenario", {}).items():
            graph.add((specification, LADERR_NS.constructs, data_ns[scenario_id]))
            for class_type, instances in scenario_data.items():
                if not isinstance(instances, dict):
                    continue
                for instance_id, props in instances.items():
                    if instance_id in {"id", "label"}:
                        continue
                    graph.add((specification, LADERR_NS.constructs, data_ns[instance_id]))

        return graph, data_ns

    @staticmethod
    def create_combined_graph(laderr_graph: Graph) -> Graph:

        combined_graph = Graph()

        schema_graph = GraphHandler._load_laderr_schema()

        combined_graph += schema_graph
        combined_graph += laderr_graph

        return combined_graph

    @staticmethod
    def create_laderr_graph(laderr_file_path: str) -> Graph:
        """
        Creates a unified RDF laderr_graph for a LaDeRR specification.

        Reads a specification file, converts metadata and data into RDF graphs, and merges them.

        :param laderr_file_path: Path to the LaDeRR specification file.
        :type laderr_file_path: str
        :return: A single RDFLib laderr_graph containing all metadata and data from the specification.
        :rtype: Graph
        """
        spec_metadata, spec_data = SpecificationHandler.read_specification(laderr_file_path)
        laderr_metadata_graph, base_uri = GraphHandler._convert_metadata_to_graph(spec_metadata, spec_data)
        laderr_data_graph = GraphHandler._convert_data_to_graph(spec_metadata, spec_data)

        # Create a new laderr_graph to store the combined information
        laderr_graph = Graph()

        # Merge metadata laderr_graph
        laderr_graph += laderr_metadata_graph

        # Merge data laderr_graph
        laderr_graph += laderr_data_graph

        # Duplicate elements in multiple scenarios
        laderr_graph = GraphHandler._replicate_shared_components_per_scenario(laderr_graph)

        # Validate base URI and bind namespaces
        laderr_graph.bind("", base_uri)  # Bind the `laderr:` namespace
        laderr_graph.bind("laderr", LADERR_NS)  # Bind the `laderr:` namespace

        return laderr_graph

    @staticmethod
    def get_base_prefix(graph: Graph) -> str:
        """
        Retrieves the base prefix (default namespace) of the RDF graph.

        The method searches for a base namespace bound to an empty prefix ("").
        If not found, it checks for the "ns1" prefix (RDFLib's default for unnamed namespaces).
        If neither is found, it falls back to "https://example.org/" as a default base URI.

        Warnings are logged when the expected prefixes are missing.

        :param graph: The RDFLib graph
        :return: The base prefix as a string.
        """
        default_base = "https://example.org/"
        ns1_prefix = None

        # First, iterate once and collect potential base URIs
        for prefix, namespace in graph.namespaces():
            if prefix == "":
                return str(namespace)  # Immediately return the correct base prefix
            if prefix == "ns1":
                ns1_prefix = str(namespace)  # Store "ns1" for later fallback

        # If no empty prefix found, fallback to "ns1" if available
        if ns1_prefix:
            logger.warning("Base URL associated with empty prefix not found. Retrieving prefix ns1 (RDFLib's default).")
            return ns1_prefix

        # Final fallback
        logger.warning("Base URL associated with empty prefix or ns1 not found. Using default: https://example.org/.")
        return default_base

    @staticmethod
    def clean_graph(graph: Graph, base_url: str) -> Graph:
        """
        Cleans the RDF graph by removing unwanted triples.

        This method removes all triples that:
        1. Have a subject that does not start with the given `base_url`.
        2. Contain any blank node (`BNode`) in the subject, predicate, or object.
        3. Are of the form `X a rdfs:Resource`, which are redundant and unnecessary.

        This ensures that only relevant triples remain in the graph, improving clarity
        and reducing unnecessary noise.

        :param graph: The RDF graph to be cleaned.
        :type graph: Graph
        :param base_url: The base URL prefix that subjects must start with to be kept.
        :type base_url: str
        :return: A cleaned RDF graph containing only relevant triples.
        :rtype: Graph
        """
        triples_to_remove = {(s, p, o) for s, p, o in graph if
                             (not str(s).startswith(base_url))  # Remove triples where subject is not in base_url
                             or isinstance(s, BNode) or isinstance(p, BNode) or isinstance(o,
                                                                                           BNode)  # Remove triples with blank nodes
                             or (p == RDF.type and o == RDFS.Resource)  # Remove "X a rdfs:Resource"
                             or (p == OWL.topObjectProperty)  # Remove "X owl:topObjectProperty Y"
                             }

        for triple in triples_to_remove:
            graph.remove(triple)

        return graph

    @staticmethod
    def split_graph_by_scenario(graph: Graph) -> dict[str, Graph]:
        """
        Splits the input graph into separate subgraphs for each Scenario.

        Returns:
            A dictionary where keys are scenario identifiers and values are RDFLib Graphs.
        """
        from rdflib import RDF

        scenario_graphs = {}
        for scenario in graph.subjects(RDF.type, LADERR_NS.Scenario):
            scenario_id = str(scenario).split("#")[-1]
            subgraph = Graph()
            subgraph.namespace_manager = graph.namespace_manager  # preserve bindings

            # Include scenario-level triples
            for triple in graph.triples((scenario, None, None)):
                subgraph.add(triple)

            # Add all components of the scenario
            for _, _, component in graph.triples((scenario, LADERR_NS.components, None)):
                for triple in graph.triples((component, None, None)):
                    subgraph.add(triple)
                for triple in graph.triples((None, None, component)):
                    subgraph.add(triple)

            scenario_graphs[scenario_id] = subgraph

        return scenario_graphs

    @staticmethod
    def _replicate_shared_components_per_scenario(graph: Graph) -> Graph:
        """
        For components included in multiple scenarios, replicate them per scenario
        by creating unique URIs (e.g., appending '_s1') and removing the original.

        :param graph: The original RDFLib graph.
        :return: A new graph with scenario-specific replicated components only.
        """
        component_scenarios = defaultdict(set)

        # Step 1: Find all components and the scenarios they appear in
        for scenario in graph.subjects(RDF.type, LADERR_NS.Scenario):
            for _, _, component in graph.triples((scenario, LADERR_NS.components, None)):
                component_scenarios[component].add(scenario)

        shared_components = {c for c, scenarios in component_scenarios.items() if len(scenarios) > 1}
        new_graph = Graph()
        new_graph.namespace_manager = graph.namespace_manager

        # Step 2: Copy all triples EXCEPT those related to shared components
        for s, p, o in graph:
            # Skip if the triple involves a shared component or points to one
            if (s in shared_components) or (o in shared_components):
                continue
            new_graph.add((s, p, o))

        # Step 3: Replicate shared components per scenario
        for component in shared_components:
            original_uri_str = str(component)

            for scenario in component_scenarios[component]:
                scenario_id = str(scenario).split("#")[-1]
                replicated_uri = URIRef(f"{original_uri_str}_{scenario_id}")

                # Log duplication
                logger.info(
                    f"Replicating shared component '{original_uri_str}' as '{replicated_uri}' for scenario '{scenario_id}'."
                )

                # Add the scenario-specific laderr:components triple
                new_graph.add((scenario, LADERR_NS.components, replicated_uri))

                # Copy outgoing triples from the original component
                for p, o in graph.predicate_objects(component):
                    if o in shared_components and scenario in component_scenarios[o]:
                        # Nested shared component — redirect that one too
                        replicated_o = URIRef(f"{str(o)}_{scenario_id}")
                        new_graph.add((replicated_uri, p, replicated_o))
                    else:
                        new_graph.add((replicated_uri, p, o))

                # Copy **only relevant incoming triples** — those not from other scenarios!
                for s2, p2 in graph.subject_predicates(component):
                    if p2 == LADERR_NS.components:
                        continue  # already handled above

                    # Special case: incoming triple from another shared component
                    if s2 in shared_components:
                        replicated_s2 = URIRef(f"{str(s2)}_{scenario_id}")
                        new_graph.add((replicated_s2, p2, replicated_uri))
                    else:
                        new_graph.add((s2, p2, replicated_uri))

        # Build reverse index: find out which components belong to which scenario
        scenario_components = defaultdict(set)
        for scenario in new_graph.subjects(RDF.type, LADERR_NS.Scenario):
            for _, _, comp in new_graph.triples((scenario, LADERR_NS.components, None)):
                scenario_components[scenario].add(comp)

        # For every non-duplicated component, check and fix scenario mismatch in object references
        for component in set(new_graph.subjects(RDF.type, LADERR_NS.Capability)):
            if "_s1" in str(component) or "_s2" in str(component):
                continue  # Skip already duplicated components

            # Identify scenario of this component
            scenario = next((s for s, comps in scenario_components.items() if component in comps), None)
            if scenario is None:
                continue

            scenario_suffix = str(scenario).split("#")[-1]

            # Get and fix all problematic object references in outgoing triples
            for p, o in list(new_graph.predicate_objects(subject=component)):
                if isinstance(o, URIRef) and (
                        o.endswith("_s1") or o.endswith("_s2")
                ) and not o.endswith(f"_{scenario_suffix}"):
                    # Remove the wrong link
                    new_graph.remove((component, p, o))

        return new_graph
