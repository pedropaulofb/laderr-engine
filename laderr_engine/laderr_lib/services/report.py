import inspect
import os
import tempfile
import textwrap

import matplotlib.pyplot as plt
from rdflib import Graph, RDF, Namespace
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas

from laderr_engine.laderr_lib.constants import LADERR_NS
from laderr_engine.laderr_lib.services.graph import GraphHandler
from laderr_engine.laderr_lib.services.visualization import VisualizationCreator


class ReportGenerator:
    """A utility class to analyze LaDeRR graphs and generate PDF reports. Cannot be instantiated."""

    PLOT_HEIGHT_CM = 12
    PLOT_WIDTH_CM = PLOT_HEIGHT_CM / 0.707  # ≈ 17 cm, A4 ratio

    RESILIENCE_INDEX_NAMES = ["Resilience Index", "Vulnerability Index", "Capabilities-to-Vulnerabilities Ratio",
        "Capabilities-to-Vulnerabilities Ratio (Enabled & Exploited)",
        "Capabilities-to-Vulnerabilities Ratio (Enabled & Not Exploited)",
        "Capabilities-to-Vulnerabilities Ratio (Disabled & Exploited)",
        "Capabilities-to-Vulnerabilities Ratio (Disabled & Not Exploited)", "Exposed Capabilities Count",
        "Exposed Capabilities Count (Enabled & Exploited)", "Exposed Capabilities Count (Enabled & Not Exploited)",
        "Exposed Capabilities Count (Disabled & Exploited)", "Exposed Capabilities Count (Disabled & Not Exploited)",
        "Per-Asset Capability Risk", "Per-Asset Capability Risk (Enabled & Exploited)",
        "Per-Asset Capability Risk (Enabled & Not Exploited)", "Per-Asset Capability Risk (Disabled & Exploited)",
        "Per-Asset Capability Risk (Disabled & Not Exploited)", "Control-to-Asset Ratio", "Threat-to-Asset Ratio",
        "Control-to-Threat Ratio", "Preserves per Resilience Ratio", "PreservesDespite per Resilience Ratio",
        "PreservesAgainst per Resilience Ratio", "Sustains per Resilience Ratio"]

    def __init__(self):
        raise RuntimeError("ReportGenerator is a static utility class and cannot be instantiated.")

    @staticmethod
    def generate_pdf_report(graph: Graph, output_path: str = "laderr_report"):
        scenario_graphs = GraphHandler.split_graph_by_scenario(graph)

        for scenario_id, scenario_graph in scenario_graphs.items():
            metrics = ReportGenerator._calculate_resilience_metrics(scenario_graph)

            scenario_output_path = f"{os.path.splitext(output_path)[0]}_{scenario_id}.pdf"
            c = canvas.Canvas(scenario_output_path, pagesize=A4)
            width, height = A4

            visualization_paths = VisualizationCreator.create_graph_visualization(scenario_graph,
                tempfile.mktemp(suffix=f"_{scenario_id}")[:-4])

            title_top_y = height - 2 * cm
            y = ReportGenerator._draw_main_title(c, f"Report for Scenario {scenario_id}", title_top_y, width)

            for visualization_path in visualization_paths:

                if visualization_path and os.path.exists(visualization_path):
                    title_bottom_y = y
                    max_vis_height = title_bottom_y - 2 * cm

                    aspect_ratio = 1.0
                    try:
                        from PIL import Image
                        with Image.open(visualization_path) as img:
                            vis_width, vis_height = img.size
                            aspect_ratio = vis_width / vis_height
                    except Exception:
                        pass

                    vis_display_width = width
                    vis_display_height = vis_display_width / aspect_ratio

                    if vis_display_height > max_vis_height:
                        vis_display_height = max_vis_height
                        vis_display_width = vis_display_height * aspect_ratio

                    x = (width - vis_display_width) / 2
                    y = title_bottom_y - vis_display_height
                    c.drawImage(visualization_path, x, y, vis_display_width, vis_display_height)
                    os.remove(visualization_path)

            ReportGenerator._draw_legend_page(c, width, height)

            c.showPage()
            chart_data = {"Entity": metrics["total_entities"], "Capability": metrics["total_capabilities"],
                "Vulnerability": metrics["total_vulnerabilities"], "Resilience": metrics["total_resiliences"], }
            colors_map = {"Entity": "lightgreen", "Capability": "lightblue", "Vulnerability": "#eb7575",
                "Resilience": "orange", }
            pie_path = tempfile.mktemp(suffix=".png")
            y, total = ReportGenerator._draw_section_title(c, "Instances per Class", sum(chart_data.values()),
                                                           height - 2 * cm, width)
            ReportGenerator._create_pie_chart(chart_data, pie_path, colors_map, "")
            c.drawImage(pie_path, 2 * cm, y - (ReportGenerator.PLOT_HEIGHT_CM - 1) * cm,
                        ReportGenerator.PLOT_WIDTH_CM * cm, ReportGenerator.PLOT_HEIGHT_CM * cm)
            c.setFont("Helvetica", 14)
            c.drawString(2.2 * cm, y, f"Total Instances: {total}")
            os.remove(pie_path)

            vuln_chart_data = {"Enabled & Exploited": metrics["exploited_enabled_vulnerabilities"],
                "Enabled & Not Exploited": metrics["not_exploited_enabled_vulnerabilities"],
                "Disabled & Exploited": metrics["exploited_disabled_vulnerabilities"],
                "Disabled & Not Exploited": metrics["not_exploited_disabled_vulnerabilities"]}
            colors_map_vuln = {"Enabled & Exploited": "orange", "Enabled & Not Exploited": "lightgreen",
                "Disabled & Exploited": "#eb7575", "Disabled & Not Exploited": "gray"}
            pie_path = tempfile.mktemp(suffix=".png")
            y, total = ReportGenerator._draw_subsection_title(c, "Vulnerabilities", metrics["total_vulnerabilities"], y,
                                                              height, width)
            ReportGenerator._create_pie_chart(vuln_chart_data, pie_path, colors_map_vuln, "")
            c.drawImage(pie_path, 2 * cm, y - (ReportGenerator.PLOT_HEIGHT_CM - 1) * cm,
                        ReportGenerator.PLOT_WIDTH_CM * cm, ReportGenerator.PLOT_HEIGHT_CM * cm)
            c.setFont("Helvetica", 14)
            c.drawString(2.2 * cm, y, f"Total Instances: {total}")
            os.remove(pie_path)

            cap_data = {"Enabled": metrics["enabled_capabilities"], "Disabled": metrics["disabled_capabilities"]}
            colors_map_cap = {"Enabled": "lightgreen", "Disabled": "#eb7575"}
            pie_path = tempfile.mktemp(suffix=".png")
            y, total = ReportGenerator._draw_subsection_title(c, "Capabilities", metrics["total_capabilities"], y,
                                                              height, width)
            ReportGenerator._create_pie_chart(cap_data, pie_path, colors_map_cap, "")
            c.drawImage(pie_path, 2 * cm, y - (ReportGenerator.PLOT_HEIGHT_CM - 1) * cm,
                        ReportGenerator.PLOT_WIDTH_CM * cm, ReportGenerator.PLOT_HEIGHT_CM * cm)
            c.setFont("Helvetica", 14)
            c.drawString(2.2 * cm, y, f"Total Instances: {total}")
            os.remove(pie_path)

            entity_data = {"Assets": metrics["assets"], "Threats": metrics["threats"], "Controls": metrics["controls"],
                "Unclassified": metrics["unclassified_entities"]}
            colors_map_entities = {"Assets": "lightgreen", "Threats": "#eb7575", "Controls": "lightblue",
                "Unclassified": "gray"}
            pie_path = tempfile.mktemp(suffix=".png")
            y, total = ReportGenerator._draw_subsection_title(c, "Entities", metrics["total_entities"], y, height,
                                                              width)
            ReportGenerator._create_pie_chart(entity_data, pie_path, colors_map_entities, "")
            c.drawImage(pie_path, 2 * cm, y - (ReportGenerator.PLOT_HEIGHT_CM - 1) * cm,
                        ReportGenerator.PLOT_WIDTH_CM * cm, ReportGenerator.PLOT_HEIGHT_CM * cm)
            c.setFont("Helvetica", 14)
            c.drawString(2.2 * cm, y, f"Total Instances: {total}")
            os.remove(pie_path)

            c.showPage()
            y, _ = ReportGenerator._draw_section_title(c, "Scenario's Indexes", None, height - 2 * cm, width)
            c.setFont("Helvetica", 14)
            c.setFont("Helvetica", 14)
            y += 0.2 * cm

            for index_name in ReportGenerator.RESILIENCE_INDEX_NAMES:
                value = metrics.get(index_name)
                if value is None:
                    continue

                formatted_value = ReportGenerator._format_metric_value(value)
                c.setFont("Helvetica", 12)
                c.drawString(2 * cm, y, f"{index_name}: {formatted_value}")
                y -= 0.4 * cm

                description = ReportGenerator._get_index_description(index_name)
                if description:
                    wrapped_lines = textwrap.wrap(description, width=100)  # adjust width if needed
                    c.setFont("Helvetica-Oblique", 10)
                    for line in wrapped_lines:
                        c.drawString(2.5 * cm, y, line)
                        y -= 0.3 * cm
                    y -= 0.2 * cm

            c.save()

    @staticmethod
    def _count_laderr_classes(graph: Graph) -> dict:
        class_counts = {}
        for s, p, o in graph.triples((None, RDF.type, None)):
            if isinstance(o, Namespace) or not str(o).startswith(str(LADERR_NS)):
                continue
            class_name = str(o).replace(str(LADERR_NS), "")
            if class_name == "Scenario":
                continue
            class_counts[class_name] = class_counts.get(class_name, 0) + 1
        return dict(sorted(class_counts.items(), key=lambda item: item[1], reverse=True))

    @staticmethod
    def _calculate_resilience_metrics(graph: Graph) -> dict:
        vulnerabilities = set(graph.subjects(RDF.type, LADERR_NS.Vulnerability))
        capabilities = set(graph.subjects(RDF.type, LADERR_NS.Capability))
        entities = set(graph.subjects(RDF.type, LADERR_NS.Entity))
        resiliences = set(graph.subjects(RDF.type, LADERR_NS.Resilience))

        disabled = LADERR_NS.disabled
        state = LADERR_NS.state
        exploits = LADERR_NS.exploits

        count_total_vul = len(vulnerabilities)
        count_total_cap = len(capabilities)

        enabled_vul = sum(1 for v in vulnerabilities if (v, state, disabled) not in graph)
        disabled_vul = count_total_vul - enabled_vul

        enabled_cap = sum(1 for c in capabilities if (c, state, disabled) not in graph)
        disabled_cap = count_total_cap - enabled_cap

        exploited_enabled = 0
        exploited_disabled = 0
        not_exploited_enabled = 0
        not_exploited_disabled = 0

        for v in vulnerabilities:
            is_disabled = (v, state, disabled) in graph
            has_exploit = bool(list(graph.subjects(exploits, v)))

            if is_disabled and not has_exploit:
                not_exploited_disabled += 1
            elif is_disabled and has_exploit:
                exploited_disabled += 1
            elif not is_disabled and not has_exploit:
                not_exploited_enabled += 1
            elif not is_disabled and has_exploit:
                exploited_enabled += 1

        resilience_numerator = (not_exploited_disabled + exploited_disabled + not_exploited_enabled)
        resilience_index = resilience_numerator / count_total_vul if count_total_vul > 0 else 0.0
        vulnerability_index = 1 - resilience_index

        assets = set(graph.subjects(RDF.type, LADERR_NS.Asset))
        threats = set(graph.subjects(RDF.type, LADERR_NS.Threat))
        controls = set(graph.subjects(RDF.type, LADERR_NS.Control))
        subtyped_entities = assets | threats | controls
        unclassified = entities - subtyped_entities

        # Advanced Indexes
        resilience_count = len(resiliences)
        vulnerabilities_count = count_total_vul
        capabilities_count = count_total_cap
        assets_count = len(assets)
        threats_count = len(threats)
        controls_count = len(controls)
        preserves_count = len(list(graph.triples((None, LADERR_NS.preserves, None))))
        preservesDespite_count = len(list(graph.triples((None, LADERR_NS.preservesDespite, None))))
        preservesAgainst_count = len(list(graph.triples((None, LADERR_NS.preservesAgainst, None))))
        sustains_count = len(list(graph.triples((None, LADERR_NS.sustains, None))))

        def get_exposed_by(vuln_set):
            return set(obj for v in vuln_set for s, p, obj in graph.triples((v, LADERR_NS.exposes, None)) if
                       (obj, RDF.type, LADERR_NS.Capability) in graph)

        # Vulnerability subsets
        enabled_exploited = [v for v in vulnerabilities if
                             (v, state, disabled) not in graph and list(graph.subjects(exploits, v))]
        enabled_not_exploited = [v for v in vulnerabilities if
                                 (v, state, disabled) not in graph and not list(graph.subjects(exploits, v))]
        disabled_exploited = [v for v in vulnerabilities if
                              (v, state, disabled) in graph and list(graph.subjects(exploits, v))]
        disabled_not_exploited = [v for v in vulnerabilities if
                                  (v, state, disabled) in graph and not list(graph.subjects(exploits, v))]

        all_exposed_capabilities = get_exposed_by(vulnerabilities)
        exposed_by_enabled_exploited = get_exposed_by(enabled_exploited)
        exposed_by_enabled_not_exploited = get_exposed_by(enabled_not_exploited)
        exposed_by_disabled_exploited = get_exposed_by(disabled_exploited)
        exposed_by_disabled_not_exploited = get_exposed_by(disabled_not_exploited)

        # Index Calculations

        indexes = {"Capabilities-to-Vulnerabilities Ratio": {
            "value": capabilities_count / vulnerabilities_count if vulnerabilities_count else 0,
            "description": "The ratio between the number of capabilities and the number of vulnerabilities across all assets."},
            "Capabilities-to-Vulnerabilities Ratio (Enabled & Exploited)": {
                "value": capabilities_count / len(enabled_exploited) if enabled_exploited else 0,
                "description": "The ratio between the number of capabilities and the number of enabled and exploited vulnerabilities across all assets."},
            "Capabilities-to-Vulnerabilities Ratio (Enabled & Not Exploited)": {
                "value": capabilities_count / len(enabled_not_exploited) if enabled_not_exploited else 0,
                "description": "The ratio between the number of capabilities and the number of enabled but not exploited vulnerabilities across all assets."},
            "Capabilities-to-Vulnerabilities Ratio (Disabled & Exploited)": {
                "value": capabilities_count / len(disabled_exploited) if disabled_exploited else 0,
                "description": "The ratio between the number of capabilities and the number of disabled and exploited vulnerabilities across all assets."},
            "Capabilities-to-Vulnerabilities Ratio (Disabled & Not Exploited)": {
                "value": capabilities_count / len(disabled_not_exploited) if disabled_not_exploited else 0,
                "description": "The ratio between the number of capabilities and the number of disabled and not exploited vulnerabilities across all assets."},
            "Exposed Capabilities Count": {"value": len(all_exposed_capabilities),
                "description": "The number of capabilities across all assets that are exposed by any vulnerability."},
            "Exposed Capabilities Count (Enabled & Exploited)": {"value": len(exposed_by_enabled_exploited),
                "description": "The number of capabilities across all assets that are exposed by enabled and exploited vulnerabilities."},
            "Exposed Capabilities Count (Enabled & Not Exploited)": {"value": len(exposed_by_enabled_not_exploited),
                "description": "The number of capabilities across all assets that are exposed by enabled but not exploited vulnerabilities."},
            "Exposed Capabilities Count (Disabled & Exploited)": {"value": len(exposed_by_disabled_exploited),
                "description": "The number of capabilities across all assets that are exposed by disabled and exploited vulnerabilities."},
            "Exposed Capabilities Count (Disabled & Not Exploited)": {"value": len(exposed_by_disabled_not_exploited),
                "description": "The number of capabilities across all assets that are exposed by disabled and not exploited vulnerabilities."},
            "Per-Asset Capability Risk": {"value": len(all_exposed_capabilities) / assets_count if assets_count else 0,
                "description": "How much exposure exists on average per asset."},
            "Per-Asset Capability Risk (Enabled & Exploited)": {
                "value": len(exposed_by_enabled_exploited) / assets_count if assets_count else 0,
                "description": "Average number of capabilities per asset that are exposed by enabled and exploited vulnerabilities."},
            "Per-Asset Capability Risk (Enabled & Not Exploited)": {
                "value": len(exposed_by_enabled_not_exploited) / assets_count if assets_count else 0,
                "description": "Average number of capabilities per asset that are exposed by enabled but not exploited vulnerabilities."},
            "Per-Asset Capability Risk (Disabled & Exploited)": {
                "value": len(exposed_by_disabled_exploited) / assets_count if assets_count else 0,
                "description": "Average number of capabilities per asset that are exposed by disabled and exploited vulnerabilities."},
            "Per-Asset Capability Risk (Disabled & Not Exploited)": {
                "value": len(exposed_by_disabled_not_exploited) / assets_count if assets_count else 0,
                "description": "Average number of capabilities per asset that are exposed by disabled and not exploited vulnerabilities."},
            "Control-to-Asset Ratio": {"value": controls_count / assets_count if assets_count else 0,
                "description": "Indicates how many controls exist per asset in the system."},
            "Threat-to-Asset Ratio": {"value": threats_count / assets_count if assets_count else 0,
                "description": "Indicates how many threats exist per asset in the system."},
            "Control-to-Threat Ratio": {"value": controls_count / threats_count if threats_count else 0,
                "description": "Indicates how many controls exist per threat in the system."},
            "Preserves per Resilience Ratio": {"value": preserves_count / resilience_count if resilience_count else 0,
                "description": "Quantifies how each resilience instance contributes to capability preservation."},
            "Resilience Index": {"value": resilience_index,
                "description": "Proportion of vulnerabilities that did not result in damage or were prevented."},
            "Vulnerability Index": {"value": 1 - resilience_index,
                "description": "Proportion of vulnerabilities that are considered active or damaging."},
            "PreservesDespite per Resilience Ratio": {
                "value": preservesDespite_count / resilience_count if resilience_count else 0,
                "description": "Quantifies how each resilience instance relates to 'preservesDespite' relations, indicating the system's tolerance mechanisms."},
            "PreservesAgainst per Resilience Ratio": {
                "value": preservesAgainst_count / resilience_count if resilience_count else 0,
                "description": "Shows the proportion of 'preservesAgainst' links per resilience, related to protective mechanisms."},
            "Sustains per Resilience Ratio": {"value": sustains_count / resilience_count if resilience_count else 0,
                "description": "Indicates how often each resilience instance sustains capabilities across assets."}}

        result = {"resilience_index": resilience_index, "vulnerability_index": vulnerability_index,
            "total_vulnerabilities": count_total_vul, "enabled_vulnerabilities": enabled_vul,
            "disabled_vulnerabilities": disabled_vul, "exploited_enabled_vulnerabilities": exploited_enabled,
            "exploited_disabled_vulnerabilities": exploited_disabled,
            "not_exploited_enabled_vulnerabilities": not_exploited_enabled,
            "not_exploited_disabled_vulnerabilities": not_exploited_disabled, "total_capabilities": count_total_cap,
            "enabled_capabilities": enabled_cap, "disabled_capabilities": disabled_cap, "total_entities": len(entities),
            "assets": assets_count, "threats": threats_count, "controls": controls_count,
            "unclassified_entities": len(unclassified), "total_resiliences": resilience_count}

        result.update(indexes)
        return result

    @staticmethod
    def _create_pie_chart(data: dict, output_path: str, colors_map: dict, title: str):

        def make_autopct(values):
            def my_autopct(pct):
                total = sum(values)
                absolute = int(round(pct * total / 100.0))
                return f"{absolute}\n({pct:.1f}%)"

            return my_autopct

        plot_height_cm = ReportGenerator.PLOT_HEIGHT_CM
        plot_width_cm = ReportGenerator.PLOT_WIDTH_CM
        fig_width_in = plot_width_cm / 2.54
        fig_height_in = plot_height_cm / 2.54

        fig, ax = plt.subplots(figsize=(fig_width_in, fig_height_in))

        # Split data into plotted and unplotted parts
        plotted_data = {k: v for k, v in data.items() if v > 0}
        plotted_labels = list(plotted_data.keys())
        plotted_sizes = list(plotted_data.values())
        plotted_colors = [colors_map.get(label, 'gray') for label in plotted_labels]

        # Create a pie chart with smaller size (2/3) by shrinking radius manually
        ax.pie(plotted_sizes, labels=None, colors=plotted_colors, autopct=make_autopct(plotted_sizes), startangle=90,
               counterclock=False, textprops={'fontsize': 12, 'weight': 'bold'}, radius=0.67)

        ax.axis("equal")  # keep pie circular

        # Construct legend with all categories (including those with value 0)
        all_labels = [f"{label} ({data[label]})" for label in data.keys()]
        legend_colors = [colors_map.get(label, 'gray') for label in data.keys()]
        patches = [plt.Line2D([0], [0], marker='o', color='w', label=l, markerfacecolor=c, markersize=10) for l, c in
                   zip(all_labels, legend_colors)]

        ax.legend(handles=patches, loc="lower center", bbox_to_anchor=(0.5, -0.15), ncol=2, fontsize=12, frameon=False)

        plt.savefig(output_path, dpi=300)
        plt.close()

    @staticmethod
    def _draw_legend_page(c: canvas.Canvas, width, height):
        c.showPage()
        y = height - 2 * cm

        # Main Title (Blue Header)
        c.setFillColor(colors.lightblue)
        c.rect(2 * cm, y, width - 4 * cm, 1.0 * cm, stroke=0, fill=1)
        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(2.2 * cm, y + 0.3 * cm, "Legend for Scenario Elements")
        y -= 2 * cm

        # Second-Level Header (Gray) - Node Types
        c.setFillColor(colors.whitesmoke)
        c.rect(2 * cm, y, width - 4 * cm, 0.8 * cm, stroke=0, fill=1)
        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(2.2 * cm, y + 0.25 * cm, "Node Types")
        y -= 1.2 * cm

        def draw_node_legend(x, y, shape, color, label):
            size = 1.0 * cm
            c.setFillColor(color)
            c.setStrokeColor(colors.black)
            c.setLineWidth(1)
            if shape == "circle":
                c.circle(x + size / 2, y + size / 2, size / 2, fill=1, stroke=1)
            elif shape == "square":
                c.rect(x, y, size, size, fill=1, stroke=1)
            elif shape == "ellipse":
                c.ellipse(x, y, x + size * 1.6, y + size, fill=1, stroke=1)
            c.setFillColor(colors.black)
            c.setFont("Helvetica", 12)
            c.drawString(x + size + 0.4 * cm, y + 0.2 * cm, label)

        node_items = [("circle", colors.lightgreen, "Enabled Capability"),
            ("circle", colors.darkgreen, "Disabled Capability"), ("circle", colors.lightcoral, "Enabled Vulnerability"),
            ("circle", colors.darkred, "Disabled Vulnerability"), ("circle", colors.orange, "Resilience"),
            ("square", colors.lightgreen, "Asset"), ("square", colors.lightblue, "Control"),
            ("square", colors.lightcoral, "Threat"), ("square", colors.gray, "Unclassified Entity"), ]

        x = 2 * cm
        for shape, color, label in node_items:
            draw_node_legend(x, y, shape, color, label)
            y -= 1.2 * cm

        # Second-Level Header (Gray) - Edge Types
        y -= 0.6 * cm
        c.setFillColor(colors.whitesmoke)
        c.rect(2 * cm, y, width - 4 * cm, 0.8 * cm, stroke=0, fill=1)
        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(2.2 * cm, y + 0.25 * cm, "Edge Types")
        y -= 1.2 * cm

        def draw_edge_legend(y, color, description):
            line_x1 = 2 * cm
            line_x2 = line_x1 + 2.5 * cm
            line_y = y + 0.5 * cm
            arrow_size = 0.35 * cm

            # Draw the edge line
            c.setStrokeColor(color)
            c.setLineWidth(2)
            c.line(line_x1, line_y, line_x2, line_y)

            # Draw filled triangle arrowhead pointing right
            arrow = c.beginPath()
            arrow.moveTo(line_x2, line_y)
            arrow.lineTo(line_x2 - arrow_size, line_y + arrow_size / 1.5)
            arrow.lineTo(line_x2 - arrow_size, line_y - arrow_size / 1.5)
            arrow.close()

            c.setFillColor(color)
            c.setStrokeColor(color)
            c.drawPath(arrow, fill=1, stroke=0)

            # Description
            c.setFont("Helvetica", 10)
            c.setFillColor(colors.black)
            c.drawString(line_x2 + 0.4 * cm, line_y - 0.2 * cm, description)

        edge_explanations = [(colors.blue, "Entity-to-entity links: protects, inhibits, threatens."),
            (colors.orange, "Resilience links: preserves, preservesAgainst, preservesDespite, sustains."),
            (colors.darkred, "A capability disables a vulnerability."),
            (colors.black, "Causal links: capability exploits, vulnerability exposes."),
            (colors.green, "No damage: cannot or did not occur."), (colors.red, "Damage: can or has occurred."),
            ("diamond-left", "Relations from Entities to their Capabilities, Vulnerabilities, or Resiliences."), ]

        for spec, description in edge_explanations:
            if spec == "diamond-left":
                # Line start
                line_x1 = 2 * cm
                line_x2 = line_x1 + 2.5 * cm
                line_y = y + 0.5 * cm
                diamond_size = 0.5 * cm  # Slightly bigger

                # Adjust diamond so its left tip aligns with line start (line_x1)
                left_tip_x = line_x1
                diamond = c.beginPath()
                diamond.moveTo(left_tip_x, line_y)  # left point
                diamond.lineTo(left_tip_x + diamond_size / 2, line_y + diamond_size / 2)  # top
                diamond.lineTo(left_tip_x + diamond_size, line_y)  # right point
                diamond.lineTo(left_tip_x + diamond_size / 2, line_y - diamond_size / 2)  # bottom
                diamond.close()

                c.setFillColor(colors.black)
                c.drawPath(diamond, fill=1, stroke=0)

                # Draw the line starting from the right edge of the diamond
                c.setStrokeColor(colors.black)
                c.setLineWidth(2)
                c.line(left_tip_x, line_y, line_x2, line_y)

                # Description
                c.setFillColor(colors.black)
                c.setFont("Helvetica", 10)
                c.drawString(line_x2 + 0.4 * cm, line_y - 0.2 * cm, description)

            else:
                draw_edge_legend(y, spec, description)

            y -= 1.2 * cm

    @staticmethod
    def _draw_main_title(c, text, y, width):
        c.setFont("Helvetica-Bold", 22)
        c.drawCentredString(width / 2, y, text)
        return y - 1.5 * cm

    @staticmethod
    def _draw_section_title(c, text, total, y, width):
        y -= 1.2 * cm
        c.setFillColor(colors.lightblue)
        c.rect(2 * cm, y, width - 4 * cm, 1.0 * cm, stroke=0, fill=1)
        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(2.2 * cm, y + 0.3 * cm, text)
        y -= 1.2 * cm
        return y, total

    @staticmethod
    def _draw_subsection_title(c, text, total, y, height, width):
        c.showPage()
        y = height - 2 * cm
        y -= 0.8 * cm
        c.setFillColor(colors.whitesmoke)
        c.rect(2 * cm, y, width - 4 * cm, 0.8 * cm, stroke=0, fill=1)
        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(2.2 * cm, y + 0.25 * cm, text)
        y -= 1.0 * cm
        return y, total

    @staticmethod
    def _get_index_description(name: str) -> str:
        index_descriptions = {
            "Resilience Index": "Proportion of vulnerabilities that did not result in damage or were prevented.",
            "Vulnerability Index": "Proportion of vulnerabilities that are considered active or damaging.",
            "Capabilities-to-Vulnerabilities Ratio": "Number of capabilities divided by the number of vulnerabilities across all assets.",
            "Capabilities-to-Vulnerabilities Ratio (Enabled & Exploited)": "Number of capabilities divided by the number of enabled and exploited vulnerabilities across all assets.",
            "Capabilities-to-Vulnerabilities Ratio (Enabled & Not Exploited)": "Number of capabilities divided by the number of enabled but not exploited vulnerabilities across all assets.",
            "Capabilities-to-Vulnerabilities Ratio (Disabled & Exploited)": "Number of capabilities divided by the number of disabled and exploited vulnerabilities across all assets.",
            "Capabilities-to-Vulnerabilities Ratio (Disabled & Not Exploited)": "Number of capabilities divided by the number of disabled and not exploited vulnerabilities across all assets.",
            "Exposed Capabilities Count": "Total number of capabilities exposed by any vulnerability.",
            "Exposed Capabilities Count (Enabled & Exploited)": "Number of capabilities exposed by enabled and exploited vulnerabilities.",
            "Exposed Capabilities Count (Enabled & Not Exploited)": "Number of capabilities exposed by enabled but not exploited vulnerabilities.",
            "Exposed Capabilities Count (Disabled & Exploited)": "Number of capabilities exposed by disabled and exploited vulnerabilities.",
            "Exposed Capabilities Count (Disabled & Not Exploited)": "Number of capabilities exposed by disabled and not exploited vulnerabilities.",
            "Per-Asset Capability Risk": "Average number of exposed capabilities per asset.",
            "Per-Asset Capability Risk (Enabled & Exploited)": "Average number of capabilities per asset exposed by enabled and exploited vulnerabilities.",
            "Per-Asset Capability Risk (Enabled & Not Exploited)": "Average number of capabilities per asset exposed by enabled but not exploited vulnerabilities.",
            "Per-Asset Capability Risk (Disabled & Exploited)": "Average number of capabilities per asset exposed by disabled and exploited vulnerabilities.",
            "Per-Asset Capability Risk (Disabled & Not Exploited)": "Average number of capabilities per asset exposed by disabled and not exploited vulnerabilities.",
            "Control-to-Asset Ratio": "Number of controls divided by the number of assets in the scenario.",
            "Threat-to-Asset Ratio": "Number of threats divided by the number of assets in the scenario.",
            "Control-to-Threat Ratio": "Number of controls divided by the number of threats in the scenario.",
            "Preserves per Resilience Ratio": "Average number of 'preserves' relations per resilience instance.",
            "PreservesDespite per Resilience Ratio": "Average number of 'preservesDespite' relations per resilience instance, indicating tolerance mechanisms.",
            "PreservesAgainst per Resilience Ratio": "Average number of 'preservesAgainst' relations per resilience instance, indicating protective mechanisms.",
            "PreservesDespite+Against per Resilience Ratio": "Average number of 'preservesDespite' and 'preservesAgainst' relations per resilience instance.",
            "Sustains per Resilience Ratio": "Average number of 'sustains' relations per resilience instance."}
        return index_descriptions.get(name, "")

    @staticmethod
    def _format_metric_value(value):
        if isinstance(value, dict):
            value = value.get("value", 0)

        percentage_indexes = [
            "Resilience Index",
            "Vulnerability Index",
        ]

        # Access the caller's local variable if available
        frame = inspect.currentframe()
        try:
            caller_locals = frame.f_back.f_locals
            current_index = caller_locals.get("index_name")
        finally:
            del frame

        if current_index in percentage_indexes:
            return f"{value:.2%}" if isinstance(value, (int, float)) else str(value)

        if isinstance(value, (int, float)) and value == int(value):
            return f"{int(value)}"

        return f"{value:.2f}"
