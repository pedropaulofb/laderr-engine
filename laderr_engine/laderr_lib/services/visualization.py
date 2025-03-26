"""
Graph Visualization Module for LaDeRR RDF Graphs.

This module provides functionality to generate visual representations of RDF graphs using Graphviz. It processes
LaDeRR RDF models, extracts entities and relationships, applies predefined styles, and outputs a PNG visualization.
"""

import graphviz
from icecream import ic
from loguru import logger
from rdflib import Graph, RDF, BNode, URIRef, RDFS

from laderr_engine.laderr_lib.constants import LADERR_NS


class GraphCreator:
    """
    Handles visualization of RDF graphs using Graphviz.

    This class provides methods to generate a visual representation of an RDF graph, styling nodes based on their
    types and relationships. The generated graph is saved as a PNG image.
    """

    @staticmethod
    def create_graph_visualization(laderr_graph: Graph, base_output_path: str) -> None:
        for scenario in laderr_graph.subjects(RDF.type, LADERR_NS.Scenario):
            scenario_id = str(scenario).split("#")[-1]
            scenario_label = laderr_graph.value(scenario, RDFS.label)
            scenario_status = laderr_graph.value(scenario, LADERR_NS.status)
            scenario_situation = laderr_graph.value(scenario, LADERR_NS.situation)

            bgcolor = GraphCreator._get_scenario_bgcolor_for_uri(laderr_graph, scenario)

            # Clean label text format
            situation_str = str(scenario_situation).split("#")[-1].upper() if scenario_situation else "UNKNOWN"
            status_str = str(scenario_status).split("#")[-1].upper() if scenario_status else "UNKNOWN"
            label_str = str(scenario_label) if scenario_label else scenario_id

            label_text = f"[{situation_str}] Scenario {label_str}: {status_str}"

            # Just pass the full label text (already constructed)
            dot = GraphCreator._initialize_graph(bgcolor, label_text)

            added_nodes = GraphCreator._process_nodes(laderr_graph, dot, scenario)
            GraphCreator._process_edges(laderr_graph, dot, added_nodes)

            if added_nodes:
                output_path = f"{base_output_path}_{scenario_id}"
                dot.render(output_path, cleanup=True)
                logger.success(f"Graph saved as {output_path}.png")
            else:
                logger.info(f"Scenario {scenario_id} skipped: no nodes to visualize.")

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
    def _initialize_graph(bgcolor: str = "white", label_text: str = "") -> graphviz.Digraph:
        """
        Initializes a Graphviz Digraph with predefined attributes, including background color and label text.
        """
        dot = graphviz.Digraph(format='png')
        dot.attr(
            dpi='300',
            fontname="Arial",
            nodesep="0.2",
            ranksep="0.4",
            labelloc="t",
            bgcolor=bgcolor,
            labeljust='l',
            fontsize="10",
            label=label_text
        )
        return dot

    @staticmethod
    def _get_scenario_bgcolor_for_uri(laderr_graph: Graph, scenario_uri: URIRef) -> str:
        scenario_colors = {
            'resilient': '#EBFFEB',
            'vulnerable': '#FDE8E8'
        }
        status = laderr_graph.value(scenario_uri, LADERR_NS.status)
        if status:
            status_value = str(status).split("#")[-1].lower()
            return scenario_colors.get(status_value, "white")
        return "white"

    @staticmethod
    def _get_scenario_type(graph: Graph, scenario: URIRef) -> str:
        situation = graph.value(scenario, LADERR_NS.situation)
        return str(situation).split("#")[-1].upper() if situation else ""

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
    def _process_nodes(graph: Graph, dot: graphviz.Digraph, scenario: URIRef) -> set:
        added_nodes = set()

        # Changed from laderr:constructs to laderr:components
        for _, _, node in graph.triples((scenario, LADERR_NS.components, None)):
            # Optionally remove the label check, or leave it if you want to enforce it
            # if (node, LADERR_NS.label, None) not in graph:
            #     continue
            added_nodes.add(node)

        for s in added_nodes:
            instance_types = [str(o).split("#")[-1] for o in graph.objects(s, RDF.type)]
            instance_id = str(s).split("#")[-1]
            is_disabled = (s, LADERR_NS.state, LADERR_NS.disabled) in graph

            if "Resilience" in instance_types:
                style = {"shape": "ellipse", "color": "black", "style": "filled", "fillcolor": "orange"}
            elif any(item in instance_types for item in ["Disposition", "Capability", "Vulnerability"]):
                style = GraphCreator._get_disposition_style(instance_types, is_disabled)
            elif "Entity" in instance_types:
                style = GraphCreator._get_entity_style(instance_types)
            else:
                style = {"shape": "ellipse", "color": "black", "style": "filled"}

            dot.node(
                instance_id,
                shape=style["shape"],
                color=style["color"],
                style=style["style"],
                penwidth=style.get("penwidth", "1"),
                fillcolor=style.get("fillcolor", "white"),
                gradientangle=style.get("gradientangle", ""),
                fixedsize="true",
                width="0.6",
                height="0.6",
                fontname="Arial",
                fontsize="6",
                label=f"<<B>{instance_id}</B>>",
                margin="0.05"
            )

        return added_nodes

    @staticmethod
    def _process_edges(graph: Graph, dot: graphviz.Digraph, added_nodes: set) -> None:
        edge_styles = {
            "protects": "blue",
            "inhibits": "blue",
            "threatens": "blue",
            "preserves": "orange",
            "preservesAgainst": "orange",
            "preservesDespite": "orange",
            "sustains": "orange",
            "cannotDamage": "green",
            "notDamaged": "green",
            "canDamage": "red",
            "damaged": "red",
            "disables": "darkred",
        }

        for s, p, o in graph:
            if s not in added_nodes or o not in added_nodes:
                continue
            if not isinstance(o, (URIRef, BNode)):
                continue
            s_id = str(s).split("#")[-1]
            o_id = str(o).split("#")[-1]
            if s_id == o_id:
                continue

            pred_label = p.split("#")[-1]
            edge_color = edge_styles.get(pred_label, "black")  # Use colored style if defined

            dot.edge(s_id, o_id, label=pred_label, fontsize="6", color=edge_color, fontcolor=edge_color)
