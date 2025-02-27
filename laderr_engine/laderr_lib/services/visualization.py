"""
Graph Visualization Module for LaDeRR RDF Graphs.

This module provides functionality to generate visual representations of RDF graphs using Graphviz. It processes
LaDeRR RDF models, extracts entities and relationships, applies predefined styles, and outputs a PNG visualization.
"""

import graphviz
from loguru import logger
from rdflib import Graph, RDF


class GraphCreator:
    """
    Handles visualization of RDF graphs using Graphviz.

    This class provides methods to generate a visual representation of an RDF graph, styling nodes based on their
    types and relationships. The generated graph is saved as a PNG image.
    """

    @staticmethod
    def create_graph_visualization(laderr_graph: Graph, output_file_path: str) -> None:
        """
        Generates a Graphviz visualization of the RDF graph and saves it as a PNG.

        This method:
        - Validates the output file path.
        - Creates a Graphviz Digraph.
        - Defines node and edge styles.
        - Processes nodes from the RDF graph and adds them to the visualization.
        - Processes relationships between nodes and adds edges with appropriate styles.
        - (Optional) Adds a text-only legend listing descriptions of node and edge styles.
        - Saves the final visualization as a PNG file.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        :param output_file_path: Path to save the output visualization (must end with '.png').
        :type output_file_path: str
        :raises ValueError: If the output file does not have a '.png' extension.
        """
        GraphCreator._validate_output_path(output_file_path)
        dot = GraphCreator._initialize_graph()

        added_nodes = GraphCreator._process_nodes(laderr_graph, dot)
        GraphCreator._process_edges(laderr_graph, dot, added_nodes)
        dot.render(output_file_path[:-4], cleanup=True)  # Remove '.png' for Graphviz
        logger.success(f"Graph saved as {output_file_path}")

    @staticmethod
    def _validate_output_path(output_file_path: str) -> None:
        """
        Validates that the output file path ends with '.png'.

        :param output_file_path: Path where the visualization will be saved.
        :type output_file_path: str
        :raises ValueError: If the output file does not have a '.png' extension.
        """
        if not output_file_path.lower().endswith(".png"):
            raise ValueError(f"Invalid file path: '{output_file_path}'. The output file must have a '.png' extension.")

    @staticmethod
    def _initialize_graph() -> graphviz.Digraph:
        """
        Initializes a Graphviz Digraph with predefined attributes.

        :return: A Graphviz Digraph instance with configured attributes.
        :rtype: graphviz.Digraph
        """
        dot = graphviz.Digraph(format='png')
        dot.attr(dpi='300', fontname="Arial", nodesep="0.2", ranksep="0.4",
                 labelloc="c")  # Ensures labels are centered vertically
        return dot

    @staticmethod
    def _process_nodes(laderr_graph: Graph, dot: graphviz.Digraph) -> set:
        """
        Processes RDF nodes, assigns styles, and adds them to the Graphviz Digraph.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        :param dot: Graphviz Digraph instance to which nodes will be added.
        :type dot: graphviz.Digraph
        :return: A set containing added node IDs to track processed nodes.
        :rtype: set
        """
        added_nodes = set()

        for subject in laderr_graph.subjects(predicate=RDF.type):
            instance_types = [str(obj).split("#")[-1] for obj in
                              laderr_graph.objects(subject=subject, predicate=RDF.type)]
            instance_id = str(subject).split("#")[-1]

            if "LaderrSpecification" in instance_types:
                continue

            if "Resilience" in instance_types:
                style = {"shape": "ellipse", "color": "white", "style": "filled", "fillcolor": "orange"}
            elif any(item in instance_types for item in ["Disposition", "Capability", "Vulnerability"]):
                style = GraphCreator._get_disposition_style(instance_types)
            elif "Entity" in instance_types:
                style = GraphCreator._get_entity_style(instance_types)
            else:
                style = {"shape": "ellipse", "color": "black", "style": "filled"}

            if instance_id not in added_nodes:
                dot.node(instance_id, shape=style["shape"], color=style["color"], style=style["style"],
                         penwidth=style.get("penwidth", "1"), fillcolor=style.get("fillcolor", "white"),
                         gradientangle=style.get("gradientangle", ""), fixedsize="true", width="0.6", height="0.6",
                         fontname="Arial", fontsize="6", label=f"<<B>{instance_id}</B>>", margin="0.05")

                added_nodes.add(instance_id)

        return added_nodes

    @staticmethod
    def _get_disposition_style(instance_types: list) -> dict:
        """
        Determines the visual style of a Disposition based on whether it is a Capability, Vulnerability, or both.

        :param instance_types: List of types associated with the disposition.
        :type instance_types: list
        :return: A dictionary containing Graphviz node style attributes.
        :rtype: dict
        """
        base_style = {"shape": "circle", "style": "filled", "color": "white"}

        if "Capability" in instance_types and "Vulnerability" in instance_types:
            return {**base_style, "fillcolor": "green:red", "style": "wedged"}
        elif "Capability" in instance_types:
            return {**base_style, "fillcolor": "green"}
        elif "Vulnerability" in instance_types:
            return {**base_style, "fillcolor": "red"}
        else:
            return {**base_style, "fillcolor": "grey"}

    @staticmethod
    def _get_entity_style(instance_types: list) -> dict:
        """
        Determines the visual style of an Entity based on its subtypes using appropriate Graphviz styles.

        :param instance_types: List of types associated with the entity.
        :type instance_types: list
        :return: A dictionary containing Graphviz node style attributes.
        :rtype: dict
        """
        node_styles = {"Entity": {"shape": "square", "color": "white", "style": "filled"}, "Asset": {"color": "green"},
                       "Control": {"color": "#789df5"}, "Threat": {"color": "red"}}

        base_style = node_styles["Entity"]
        entity_types = [t for t in ["Asset", "Control", "Threat"] if t in instance_types]

        if not entity_types:
            return {**base_style, "fillcolor": "grey", "style": "filled"}

        if len(entity_types) == 1:
            return {**base_style, "fillcolor": node_styles[entity_types[0]]["color"], "style": "filled"}

        if len(entity_types) == 2:
            return {**base_style,
                    "fillcolor": f"{node_styles[entity_types[0]]['color']}:{node_styles[entity_types[1]]['color']}",
                    "style": "striped"}

        if len(entity_types) == 3:
            return {**base_style,
                    "fillcolor": f"{node_styles['Asset']['color']};0.33:{node_styles['Control']['color']};0.33:{node_styles['Threat']['color']};0.34",
                    "style": "striped"}

        return base_style  # Fallback, should not be reached

    @staticmethod
    def _process_edges(laderr_graph: Graph, dot: graphviz.Digraph, added_nodes: set) -> None:
        """
        Processes RDF relationships, assigns edge styles, and adds them to the Graphviz Digraph.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        :param dot: Graphviz Digraph instance to which edges will be added.
        :type dot: graphviz.Digraph
        :param added_nodes: Set of added node IDs to ensure valid edges.
        :type added_nodes: set
        """

        edge_styles = {"protects": "blue", "inhibits": "blue", "threatens": "blue", "preserves": "orange",
                       "preservesAgainst": "orange", "preservesDespite": "orange", "sustains": "orange", }

        for subject, predicate, obj in laderr_graph:
            subject_id = str(subject).split("#")[-1]
            obj_id = str(obj).split("#")[-1]
            predicate_label = predicate.split("#")[-1]

            if subject_id in added_nodes and obj_id in added_nodes and subject_id != obj_id:
                edge_color = edge_styles.get(predicate_label, "black")
                dot.edge(subject_id, obj_id, label=predicate_label, fontsize="6", color=edge_color,
                         fontcolor=edge_color)
