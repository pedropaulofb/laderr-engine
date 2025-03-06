"""
Graph Visualization Module for LaDeRR RDF Graphs.

This module provides functionality to generate visual representations of RDF graphs using Graphviz. It processes
LaDeRR RDF models, extracts entities and relationships, applies predefined styles, and outputs a PNG visualization.
"""

import graphviz
from loguru import logger
from rdflib import Graph, RDF

from laderr_engine.laderr_lib.constants import LADERR_NS


class GraphCreator:
    """
    Handles visualization of RDF graphs using Graphviz.

    This class provides methods to generate a visual representation of an RDF graph, styling nodes based on their
    types and relationships. The generated graph is saved as a PNG image.
    """

    @staticmethod
    def create_graph_visualization(laderr_graph: Graph, output_file_path: str) -> None:
        """
        Generates a Graphviz visualization of the RDF graph and saves it as a PNG, applying scenario-based background color.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        :param output_file_path: Path to save the output visualization (must end with '.png').
        :type output_file_path: str
        :raises ValueError: If the output file does not have a '.png' extension.
        """
        GraphCreator._validate_output_path(output_file_path)
        bgcolor = GraphCreator._get_scenario_bgcolor(laderr_graph)

        # Get the scenario type explicitly
        scenario_type = ""
        for specification in laderr_graph.subjects(RDF.type, LADERR_NS.LaderrSpecification):
            scenario = laderr_graph.value(specification, LADERR_NS.scenario)
            if scenario:
                scenario_type = str(scenario).split("#")[-1].upper()
                break

        dot = GraphCreator._initialize_graph(bgcolor, scenario_type)

        added_nodes = GraphCreator._process_nodes(laderr_graph, dot)
        GraphCreator._process_edges(laderr_graph, dot, added_nodes)
        dot.render(output_file_path[:-4], cleanup=True)
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
    def _initialize_graph(bgcolor: str = "white", scenario_type: str = "") -> graphviz.Digraph:
        """
        Initializes a Graphviz Digraph with predefined attributes, including background color and scenario label.

        :param bgcolor: Background color for the graph visualization.
        :type bgcolor: str
        :param scenario_type: Scenario type label to display on the upper-left corner.
        :type scenario_type: str
        :return: A Graphviz Digraph instance with configured attributes.
        :rtype: graphviz.Digraph
        """
        dot = graphviz.Digraph(format='png')
        dot.attr(dpi='300', fontname="Arial", nodesep="0.2", ranksep="0.4",
                 labelloc="t", bgcolor=bgcolor, labeljust='l', fontsize="10",
                 label=f"{scenario_type.upper()} scenario" if scenario_type else "")
        return dot

    @staticmethod
    def _get_scenario_bgcolor(laderr_graph: Graph) -> str:
        """
        Determines the background color of the visualization based on the LaderrSpecification scenario.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        :return: Hex color code for background.
        :rtype: str
        """
        scenario_colors = {
            'operational': '#FFFFFF',  # white
            'incident': '#E6E6E3',  # very light grey
            'resilient': '#EBFFEB',  # very light green
            'not_resilient': '#FDE8E8'  # very light red
        }

        for specification in laderr_graph.subjects(RDF.type, LADERR_NS.LaderrSpecification):
            scenario = laderr_graph.value(specification, LADERR_NS.scenario)
            if scenario:
                scenario_type = str(scenario).split("#")[-1].lower()
                return scenario_colors.get(scenario_type, "white")

        return "white"  # Default background color

    @staticmethod
    def _process_nodes(laderr_graph: Graph, dot: graphviz.Digraph) -> set:
        """
        Processes RDF nodes, assigns styles based on their types and states (enabled/disabled), and adds them to the Graphviz Digraph.

        Dispositions (Capabilities and Vulnerabilities) have different colors depending on whether they are enabled or disabled:
        - Enabled capabilities: light green
        - Disabled capabilities: dark green
        - Enabled vulnerabilities: light red (lightcoral)
        - Disabled vulnerabilities: dark red

        If a disposition is both a Capability and a Vulnerability, it uses a 50%-50% striped color, combining both colors.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        :param dot: Graphviz Digraph instance to which nodes will be added.
        :type dot: graphviz.Digraph
        :return: A set containing added node IDs to track processed nodes.
        :rtype: set
        """
        added_nodes = set()
        disabled_state = LADERR_NS.disabled

        for subject in laderr_graph.subjects(predicate=RDF.type):
            instance_types = [str(obj).split("#")[-1] for obj in
                              laderr_graph.objects(subject=subject, predicate=RDF.type)]
            instance_id = str(subject).split("#")[-1]

            if "LaderrSpecification" in instance_types:
                continue

            is_disabled = (subject, LADERR_NS.state, disabled_state) in laderr_graph

            if "Resilience" in instance_types:
                style = {"shape": "ellipse", "color": "black", "style": "filled", "fillcolor": "orange"}
            elif any(item in instance_types for item in ["Disposition", "Capability", "Vulnerability"]):
                style = GraphCreator._get_disposition_style(instance_types, is_disabled)
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
    def _get_disposition_style(instance_types: list, is_disabled: bool) -> dict:
        """
        Determines the visual style of a Disposition based on whether it is a Capability, Vulnerability, or both,
        and whether it is enabled or disabled.

        - Enabled capabilities are light green.
        - Disabled capabilities are dark green.
        - Enabled vulnerabilities are light red (lightcoral).
        - Disabled vulnerabilities are dark red.
        - If the disposition is both a capability and a vulnerability, it uses a striped color:
            - Enabled: light green and light red (lightcoral)
            - Disabled: dark green and dark red

        :param instance_types: List of types associated with the disposition.
        :type instance_types: list
        :param is_disabled: Whether the disposition is currently disabled.
        :type is_disabled: bool
        :return: A dictionary containing Graphviz node style attributes.
        :rtype: dict
        """
        base_style = {"shape": "circle", "style": "filled", "color": "black"}

        is_capability = "Capability" in instance_types
        is_vulnerability = "Vulnerability" in instance_types

        if is_capability and is_vulnerability:
            if is_disabled:
                fillcolor = "darkgreen:darkred"
            else:
                fillcolor = "lightgreen:lightcoral"
            style = "wedged"
        elif is_capability:
            fillcolor = "darkgreen" if is_disabled else "lightgreen"
            style = "filled"
        elif is_vulnerability:
            fillcolor = "darkred" if is_disabled else "lightcoral"
            style = "filled"
        else:
            fillcolor = "grey"
            style = "filled"

        return {**base_style, "fillcolor": fillcolor, "style": style}

    @staticmethod
    def _get_entity_style(instance_types: list) -> dict:
        """
        Determines the visual style of an Entity based on its subtypes using appropriate Graphviz styles.

        :param instance_types: List of types associated with the entity.
        :type instance_types: list
        :return: A dictionary containing Graphviz node style attributes.
        :rtype: dict
        """
        node_styles = {"Entity": {"shape": "square", "color": "black", "style": "filled"},
                       "Asset": {"color": "lightgreen"},
                       "Control": {"color": "#789df5"}, "Threat": {"color": "lightcoral"}}

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
