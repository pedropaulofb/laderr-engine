from rdflib import Graph, RDF, Namespace
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib import colors
import matplotlib.pyplot as plt
import pandas as pd
import tempfile
import os
import matplotlib.ticker as ticker

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

        resilience_numerator = (
            count_disabled_no_exploit +
            count_disabled_with_exploit +
            count_enabled_no_exploit
        )
        resilience_index = resilience_numerator / count_total_vul if count_total_vul > 0 else 0.0
        vulnerability_index = 1 - resilience_index

        assets = set(graph.subjects(RDF.type, LADERR_NS.Asset))
        threats = set(graph.subjects(RDF.type, LADERR_NS.Threat))
        controls = set(graph.subjects(RDF.type, LADERR_NS.Control))
        subtyped_entities = assets | threats | controls
        unclassified = entities - subtyped_entities

        return {
            "resilience_index": f"{resilience_index:.2%}",
            "vulnerability_index": f"{vulnerability_index:.2%}",
            "total_vulnerabilities": count_total_vul,
            "enabled_vulnerabilities": enabled_vul,
            "disabled_vulnerabilities": disabled_vul,
            "exploited_enabled_vulnerabilities": exploited_enabled,
            "exploited_disabled_vulnerabilities": exploited_disabled,
            "not_exploited_enabled_vulnerabilities": not_exploited_enabled,
            "not_exploited_disabled_vulnerabilities": not_exploited_disabled,
            "total_capabilities": count_total_cap,
            "enabled_capabilities": enabled_cap,
            "disabled_capabilities": disabled_cap,
            "total_entities": len(entities),
            "assets": len(assets),
            "threats": len(threats),
            "controls": len(controls),
            "unclassified_entities": len(unclassified),
        }

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

            y = draw_main_title(c, f"Scenario: {scenario_id}", height - 2 * cm)

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
            y, total = draw_section_title(c, "Instances per Class", sum(chart_data.values()), y)
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

            # Last Page: Visualization
            if visualization_path and os.path.exists(visualization_path):
                c.showPage()
                c.drawImage(visualization_path, 3 * cm, 4 * cm, width - 6 * cm, 14 * cm, preserveAspectRatio=True)
                c.setFont("Helvetica-Bold", 12)
                c.drawCentredString(width / 2, 2.5 * cm, f"Scenario {scenario_id} Representation")
                os.remove(visualization_path)

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
        wedges, texts, autotexts = ax.pie(
            plotted_sizes,
            labels=None,
            colors=plotted_colors,
            autopct=make_autopct(plotted_sizes),
            startangle=90,
            counterclock=False,
            textprops={'fontsize': 12, 'weight': 'bold'},
            radius=0.67
        )

        ax.axis("equal")  # keep pie circular

        # Construct legend with all categories (including those with value 0)
        all_labels = [f"{label} ({data[label]})" for label in data.keys()]
        legend_colors = [colors_map.get(label, 'gray') for label in data.keys()]
        patches = [plt.Line2D([0], [0], marker='o', color='w', label=l,
                              markerfacecolor=c, markersize=10)
                   for l, c in zip(all_labels, legend_colors)]

        ax.legend(
            handles=patches,
            loc="lower center",
            bbox_to_anchor=(0.5, -0.15),
            ncol=2,
            fontsize=12,
            frameon=False
        )

        plt.savefig(output_path, dpi=300)
        plt.close()
