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
    def create_graph_visualization(
            laderr_graph: Graph, output_file_path: str, include_legend: bool = False) -> None:
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
        :param include_legend: Whether to include a text-only legend listing descriptions of node and edge styles.
        :type include_legend: bool
        :raises ValueError: If the output file does not have a '.png' extension.
        """
        GraphCreator._validate_output_path(output_file_path)
        dot = GraphCreator._initialize_graph()
        node_styles, edge_styles = GraphCreator._define_styles()

        added_nodes = GraphCreator._process_nodes(laderr_graph, dot, node_styles)
        GraphCreator._process_edges(laderr_graph, dot, added_nodes, edge_styles)
        if include_legend:
            GraphCreator._add_text_legend(dot, node_styles, edge_styles)
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
        dot.attr(dpi='300', fontname="Arial", nodesep="0.5", ranksep="0.75")
        return dot

    @staticmethod
    def _define_styles() -> tuple[dict, dict]:
        """
        Defines node and edge styles used in the visualization.

        :return: A tuple containing dictionaries for node styles and edge styles.
        :rtype: tuple[dict, dict]
        """
        node_styles = {
            "Entity": {"shape": "square", "color": "lightblue", "style": "filled", "width": "1.2", "height": "1.2"},
            "Capability": {"shape": "circle", "color": "green", "style": "filled", "width": "1.2", "height": "1.2"},
            "Vulnerability": {"shape": "circle", "color": "red", "style": "filled", "width": "1.2", "height": "1.2"},
            "Resilience": {"shape": "doublecircle", "color": "orange", "style": "filled", "width": "1.2",
                           "height": "1.2"},
            "Mixed": {"shape": "circle", "color": "yellow", "style": "filled", "width": "1.2", "height": "1.2"},
        }

        edge_styles = {
            "protects": "blue", "inhibits": "blue", "threatens": "blue",
            "preserves": "orange", "preservesAgainst": "orange", "preservesDespite": "orange",
            "sustains": "orange",
        }

        return node_styles, edge_styles

    @staticmethod
    def _process_nodes(laderr_graph: Graph, dot: graphviz.Digraph, node_styles: dict) -> set:
        """
        Processes RDF nodes, assigns styles, and adds them to the Graphviz Digraph.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        :param dot: Graphviz Digraph instance to which nodes will be added.
        :type dot: graphviz.Digraph
        :param node_styles: Dictionary defining styles for different node types.
        :type node_styles: dict
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
                style = node_styles["Resilience"]
            elif "Capability" in instance_types and "Vulnerability" in instance_types:
                style = node_styles["Mixed"]
            elif "Capability" in instance_types:
                style = node_styles["Capability"]
            elif "Vulnerability" in instance_types:
                style = node_styles["Vulnerability"]
            elif "Entity" in instance_types:
                style = node_styles["Entity"]
            else:
                style = {"shape": "ellipse", "color": "black", "style": "filled", "width": "1.2", "height": "1.2"}

            if instance_id not in added_nodes:
                dot.node(
                    instance_id, instance_id,
                    shape=style["shape"], color=style["color"], style=style["style"],
                    fixedsize="true", width=style["width"], height=style["height"]
                )
                added_nodes.add(instance_id)

        return added_nodes

    @staticmethod
    def _process_edges(laderr_graph: Graph, dot: graphviz.Digraph, added_nodes: set, edge_styles: dict) -> None:
        """
        Processes RDF relationships, assigns edge styles, and adds them to the Graphviz Digraph.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        :param dot: Graphviz Digraph instance to which edges will be added.
        :type dot: graphviz.Digraph
        :param added_nodes: Set of added node IDs to ensure valid edges.
        :type added_nodes: set
        :param edge_styles: Dictionary defining styles for different edge types.
        :type edge_styles: dict
        """
        for subject, predicate, obj in laderr_graph:
            subject_id = str(subject).split("#")[-1]
            obj_id = str(obj).split("#")[-1]
            predicate_label = predicate.split("#")[-1]

            if subject_id in added_nodes and obj_id in added_nodes and subject_id != obj_id:
                edge_color = edge_styles.get(predicate_label, "black")
                dot.edge(subject_id, obj_id, label=predicate_label, fontsize="10", color=edge_color,
                         fontcolor=edge_color)

    @staticmethod
    def _add_text_legend(dot: graphviz.Digraph, node_styles: dict, edge_styles: dict) -> None:
        """
        Adds a text-only legend to the Graphviz visualization, listing node and edge types with their corresponding descriptions.

        :param dot: Graphviz Digraph instance where the legend will be added.
        :type dot: graphviz.Digraph
        :param node_styles: Dictionary defining styles for different node types.
        :type node_styles: dict
        :param edge_styles: Dictionary defining styles for different edge types.
        :type edge_styles: dict
        """
        with dot.subgraph(name="cluster_legend") as legend:
            legend.attr(label="Legend", fontsize="14", color="black", style="dashed", margin="0.3")

            # Define a table-style label for the legend
            legend_label = """<
                <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
                    <TR><TD><B>Symbol</B></TD><TD><B>Meaning</B></TD></TR>
            """

            # ---- NODE SYMBOLS ----
            for label, style in node_styles.items():
                symbol_desc = f"{style['color']} {style['shape']}"  # e.g., "blue square"
                legend_label += f'<TR><TD>{symbol_desc}</TD><TD>{label}</TD></TR>'

            # ---- EDGE SYMBOLS ----
            for label, color in edge_styles.items():
                symbol_desc = f"{color} line"  # e.g., "red line"
                legend_label += f'<TR><TD>{symbol_desc}</TD><TD>{label} relation</TD></TR>'

            legend_label += "</TABLE>>"

            # Add a single legend node containing the text
            legend.node("text_legend", label=legend_label, shape="plaintext", fontsize="10")
