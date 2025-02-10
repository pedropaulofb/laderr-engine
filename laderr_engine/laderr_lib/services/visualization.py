import graphviz
from loguru import logger
from rdflib import Graph, RDF


class GraphCreator:
    """
    Handles visualization of RDF graphs using Graphviz.
    """

    @staticmethod
    def create_graph_visualization(laderr_graph: Graph, output_file_path: str) -> None:
        """
        Generates a Graphviz visualization of the RDF graph and saves it as a PNG.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        :param output_file_path: Path to save the output visualization (must end with '.png').
        :type output_file_path: str
        :raises ValueError: If the output file does not have a '.png' extension.
        """

        # Validate that output file has a .png extension
        if not output_file_path.lower().endswith(".png"):
            raise ValueError(f"Invalid file path: '{output_file_path}'. The output file must have a '.png' extension.")

        # Create Graphviz Digraph
        dot = graphviz.Digraph(format='png')  # Use PNG format
        dot.attr(dpi='300', fontname="Arial")

        # Define node styles
        node_styles = {
            "Object": {"shape": "square", "color": "blue", "style": "filled"},
            "Capability": {"shape": "circle", "color": "green", "style": "filled"},
            "Vulnerability": {"shape": "circle", "color": "red", "style": "filled"},
            "Resilience": {"shape": "doublecircle", "color": "orange", "style": "filled"},
            "Mixed": {"shape": "circle", "color": "yellow", "style": "filled"},  # Both Capability and Vulnerability
        }

        # Define edge styles
        edge_styles = {
            "protects": "red",
            "inhibits": "red",
            "threatens": "red",
            "preserves": "orange",
            "preservesAgainst": "orange",
            "preservesDespite": "orange",
            "sustains": "orange",
        }

        # Track added nodes to avoid duplicate edges
        added_nodes = set()

        # Process nodes
        for subject in laderr_graph.subjects(predicate=RDF.type):
            instance_types = [
                str(obj).split("#")[-1]
                for obj in laderr_graph.objects(subject=subject, predicate=RDF.type)
            ]
            instance_id = str(subject).split("#")[-1]

            if "Resilience" in instance_types:
                style = node_styles["Resilience"]
                dot.node(
                    instance_id,
                    instance_id,
                    shape=style["shape"],
                    color=style["color"],
                    style=style["style"],
                    fixedsize="true",  # Fix the size of the node
                    width="0.5"  # Adjust the width as needed (smaller value for smaller node)
                )

            # Determine the style for the node
            if "Resilience" in instance_types:
                style = node_styles["Resilience"]
            elif "Capability" in instance_types and "Vulnerability" in instance_types:
                style = node_styles["Mixed"]  # Yellow for both
            elif "Capability" in instance_types:
                style = node_styles["Capability"]
            elif "Vulnerability" in instance_types:
                style = node_styles["Vulnerability"]
            elif "Object" in instance_types:
                style = node_styles["Object"]
            else:
                style = {"shape": "ellipse", "color": "black", "style": "filled"}  # Default style

            # Skip RiskEntity and RiskSpecification

            if "LaderrSpecification" in instance_types:
                continue

            # Add node
            if instance_id not in added_nodes:
                dot.node(instance_id, instance_id, shape=style["shape"], color=style["color"], style=style["style"])
                added_nodes.add(instance_id)

        # Process relationships (edges)
        for subject, predicate, obj in laderr_graph:
            subject_id = str(subject).split("#")[-1]
            obj_id = str(obj).split("#")[-1]
            predicate_label = predicate.split("#")[-1]

            # Ensure valid node IDs and avoid self-loops
            if subject_id in added_nodes and obj_id in added_nodes and subject_id != obj_id:
                edge_color = edge_styles.get(predicate_label, "black")
                dot.edge(subject_id, obj_id, label=predicate_label, fontsize="8", color=edge_color,
                         fontcolor=edge_color)

        # Save output
        dot.render(output_file_path[:-4], cleanup=True)  # Remove '.png' for Graphviz
        logger.success(f"Graph saved as {output_file_path}")
