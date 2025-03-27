import os
import tempfile

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

    def __init__(self):
        raise RuntimeError("ReportGenerator is a static utility class and cannot be instantiated.")

    @staticmethod
    def count_laderr_classes(graph: Graph) -> dict:
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
    def calculate_resilience_metrics(graph: Graph) -> dict:
        vulnerabilities = set(graph.subjects(RDF.type, LADERR_NS.Vulnerability))
        capabilities = set(graph.subjects(RDF.type, LADERR_NS.Capability))
        entities = set(graph.subjects(RDF.type, LADERR_NS.Entity))

        disabled = LADERR_NS.disabled
        state = LADERR_NS.state
        exploits = LADERR_NS.exploits

        count_total_vul = len(vulnerabilities)
        count_total_cap = len(capabilities)

        enabled_vul = sum(1 for v in vulnerabilities if (v, state, disabled) not in graph)
        disabled_vul = count_total_vul - enabled_vul

        enabled_cap = sum(1 for c in capabilities if (c, state, disabled) not in graph)
        disabled_cap = count_total_cap - enabled_cap

        count_disabled_no_exploit = 0
        count_disabled_with_exploit = 0
        count_enabled_no_exploit = 0

        exploited_enabled = 0
        exploited_disabled = 0
        not_exploited_enabled = 0
        not_exploited_disabled = 0

        for v in vulnerabilities:
            is_disabled = (v, state, disabled) in graph
            has_exploit = bool(list(graph.subjects(exploits, v)))

            if is_disabled and not has_exploit:
                count_disabled_no_exploit += 1
                not_exploited_disabled += 1
            elif is_disabled and has_exploit:
                count_disabled_with_exploit += 1
                exploited_disabled += 1
            elif not is_disabled and not has_exploit:
                count_enabled_no_exploit += 1
                not_exploited_enabled += 1
            elif not is_disabled and has_exploit:
                exploited_enabled += 1

        resilience_numerator = (count_disabled_no_exploit + count_disabled_with_exploit + count_enabled_no_exploit)
        resilience_index = resilience_numerator / count_total_vul if count_total_vul > 0 else 0.0
        vulnerability_index = 1 - resilience_index

        assets = set(graph.subjects(RDF.type, LADERR_NS.Asset))
        threats = set(graph.subjects(RDF.type, LADERR_NS.Threat))
        controls = set(graph.subjects(RDF.type, LADERR_NS.Control))
        subtyped_entities = assets | threats | controls
        unclassified = entities - subtyped_entities

        return {"resilience_index": f"{resilience_index:.2%}", "vulnerability_index": f"{vulnerability_index:.2%}",
            "total_vulnerabilities": count_total_vul, "enabled_vulnerabilities": enabled_vul,
            "disabled_vulnerabilities": disabled_vul, "exploited_enabled_vulnerabilities": exploited_enabled,
            "exploited_disabled_vulnerabilities": exploited_disabled,
            "not_exploited_enabled_vulnerabilities": not_exploited_enabled,
            "not_exploited_disabled_vulnerabilities": not_exploited_disabled, "total_capabilities": count_total_cap,
            "enabled_capabilities": enabled_cap, "disabled_capabilities": disabled_cap, "total_entities": len(entities),
            "assets": len(assets), "threats": len(threats), "controls": len(controls),
            "unclassified_entities": len(unclassified), }

    @staticmethod
    def generate_pdf_report(graph: Graph, output_path: str = "laderr_class_report.pdf"):
        scenario_graphs = GraphHandler.split_graph_by_scenario(graph)

        c = canvas.Canvas(output_path, pagesize=A4)
        width, height = A4

        def draw_main_title(c, text, y):
            c.setFont("Helvetica-Bold", 22)
            c.drawCentredString(width / 2, y, text)
            return y - 1.5 * cm

        def draw_section_title(c, text, total, y):
            y -= 1.2 * cm
            c.setFillColor(colors.lightblue)
            c.rect(2 * cm, y, width - 4 * cm, 1.0 * cm, stroke=0, fill=1)
            c.setFillColor(colors.black)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(2.2 * cm, y + 0.3 * cm, text)
            y -= 1.2 * cm
            return y, total

        def draw_subsection_title(c, text, total, y):
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

        for scenario_id, scenario_graph in scenario_graphs.items():
            metrics = ReportGenerator.calculate_resilience_metrics(scenario_graph)

            visualization_path = VisualizationCreator.create_graph_visualization(
                scenario_graph, tempfile.mktemp(suffix=f"_{scenario_id}")[:-4]
            )

            title_top_y = height - 2 * cm
            y = draw_main_title(c, f"Report for Scenario {scenario_id}", title_top_y)

            if visualization_path and os.path.exists(visualization_path):
                title_bottom_y = y
                max_vis_height = title_bottom_y - 2 * cm  # 2 cm bottom margin

                aspect_ratio = 1.0  # fallback aspect ratio
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

            # Add legend page
            ReportGenerator._draw_legend_page(c, width, height)

            c.showPage()

            # SECTION: Classes
            chart_data = {
                "Entity": metrics["total_entities"],
                "Capability": metrics["total_capabilities"],
                "Vulnerability": metrics["total_vulnerabilities"]
            }
            colors_map = {
                "Entity": "lightgreen",
                "Capability": "lightblue",
                "Vulnerability": "#eb7575"
            }
            pie_path = tempfile.mktemp(suffix=".png")
            y, total = draw_section_title(c, "Instances per Class", sum(chart_data.values()), height - 2 * cm)
            ReportGenerator._create_pie_chart(chart_data, pie_path, colors_map, "")
            c.drawImage(pie_path, 2 * cm, y - (ReportGenerator.PLOT_HEIGHT_CM - 1) * cm,
                        ReportGenerator.PLOT_WIDTH_CM * cm, ReportGenerator.PLOT_HEIGHT_CM * cm)
            c.setFont("Helvetica", 14)
            c.drawString(2.2 * cm, y, f"Total Instances: {total}")
            os.remove(pie_path)

            # SUBSECTION: Vulnerabilities
            vuln_chart_data = {
                "Enabled & Exploited": metrics["exploited_enabled_vulnerabilities"],
                "Enabled & Not Exploited": metrics["not_exploited_enabled_vulnerabilities"],
                "Disabled & Exploited": metrics["exploited_disabled_vulnerabilities"],
                "Disabled & Not Exploited": metrics["not_exploited_disabled_vulnerabilities"]
            }
            colors_map_vuln = {
                "Enabled & Exploited": "orange",
                "Enabled & Not Exploited": "lightgreen",
                "Disabled & Exploited": "#eb7575",
                "Disabled & Not Exploited": "gray"
            }
            pie_path = tempfile.mktemp(suffix=".png")
            y, total = draw_subsection_title(c, "Vulnerabilities", metrics["total_vulnerabilities"], y)
            ReportGenerator._create_pie_chart(vuln_chart_data, pie_path, colors_map_vuln, "")
            c.drawImage(pie_path, 2 * cm, y - (ReportGenerator.PLOT_HEIGHT_CM - 1) * cm,
                        ReportGenerator.PLOT_WIDTH_CM * cm, ReportGenerator.PLOT_HEIGHT_CM * cm)
            c.setFont("Helvetica", 14)
            c.drawString(2.2 * cm, y, f"Total Instances: {total}")
            os.remove(pie_path)

            # SUBSECTION: Capabilities
            cap_data = {
                "Enabled": metrics["enabled_capabilities"],
                "Disabled": metrics["disabled_capabilities"]
            }
            colors_map_cap = {
                "Enabled": "lightgreen",
                "Disabled": "#eb7575"
            }
            pie_path = tempfile.mktemp(suffix=".png")
            y, total = draw_subsection_title(c, "Capabilities", metrics["total_capabilities"], y)
            ReportGenerator._create_pie_chart(cap_data, pie_path, colors_map_cap, "")
            c.drawImage(pie_path, 2 * cm, y - (ReportGenerator.PLOT_HEIGHT_CM - 1) * cm,
                        ReportGenerator.PLOT_WIDTH_CM * cm, ReportGenerator.PLOT_HEIGHT_CM * cm)
            c.setFont("Helvetica", 14)
            c.drawString(2.2 * cm, y, f"Total Instances: {total}")
            os.remove(pie_path)

            # SUBSECTION: Entities
            entity_data = {
                "Assets": metrics["assets"],
                "Threats": metrics["threats"],
                "Controls": metrics["controls"],
                "Unclassified": metrics["unclassified_entities"]
            }
            colors_map_entities = {
                "Assets": "lightgreen",
                "Threats": "#eb7575",
                "Controls": "lightblue",
                "Unclassified": "gray"
            }
            pie_path = tempfile.mktemp(suffix=".png")
            y, total = draw_subsection_title(c, "Entities", metrics["total_entities"], y)
            ReportGenerator._create_pie_chart(entity_data, pie_path, colors_map_entities, "")
            c.drawImage(pie_path, 2 * cm, y - (ReportGenerator.PLOT_HEIGHT_CM - 1) * cm,
                        ReportGenerator.PLOT_WIDTH_CM * cm, ReportGenerator.PLOT_HEIGHT_CM * cm)
            c.setFont("Helvetica", 14)
            c.drawString(2.2 * cm, y, f"Total Instances: {total}")
            os.remove(pie_path)

            # SECTION: Indexes
            c.showPage()
            y, _ = draw_section_title(c, "Resilience & Vulnerability Indexes", None, height - 2 * cm)
            c.setFont("Helvetica", 14)
            c.drawString(2 * cm, y, f"Resilience Index: {metrics['resilience_index']}")
            y -= 0.6 * cm
            c.drawString(2 * cm, y, f"Vulnerability Index: {metrics['vulnerability_index']}")

        c.save()



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
        ax.pie(plotted_sizes, labels=None, colors=plotted_colors,
            autopct=make_autopct(plotted_sizes), startangle=90, counterclock=False,
            textprops={'fontsize': 12, 'weight': 'bold'}, radius=0.67)

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

        node_items = [
            ("circle", colors.lightgreen, "Enabled Capability"),
            ("circle", colors.darkgreen, "Disabled Capability"),
            ("circle", colors.lightcoral, "Enabled Vulnerability"),
            ("circle", colors.darkred, "Disabled Vulnerability"),
            ("circle", colors.orange, "Resilience"),
            ("square", colors.lightgreen, "Asset"),
            ("square", colors.lightblue, "Control"),
            ("square", colors.lightcoral, "Threat"),
            ("square", colors.gray, "Unclassified Entity"),
        ]

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

        edge_explanations = [
            (colors.blue, "Entity-to-entity links: protects, inhibits, threatens."),
            (colors.orange, "Resilience links: preserves, preservesAgainst, preservesDespite, sustains."),
            (colors.darkred, "A capability disables a vulnerability."),
            (colors.black, "Causal links: capability exploits, vulnerability exposes."),
            (colors.green, "No damage: cannot or did not occur."),
            (colors.red, "Damage: can or has occurred."),
            ("diamond-left", "Relations from Entities to their Capabilities, Vulnerabilities, or Resiliences."),
        ]

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
