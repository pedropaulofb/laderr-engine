from rdflib import Graph, RDF, Namespace
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
import matplotlib.pyplot as plt
import pandas as pd
import tempfile
import os

from laderr_engine.laderr_lib.constants import LADERR_NS


class ReportGenerator:
    """A utility class to analyze LaDeRR graphs and generate PDF reports. Cannot be instantiated."""

    def __init__(self):
        raise RuntimeError("ReportGenerator is a static utility class and cannot be instantiated.")

    @staticmethod
    def count_laderr_classes(graph: Graph) -> dict:
        class_counts = {}
        for s, p, o in graph.triples((None, RDF.type, None)):
            if isinstance(o, Namespace) or not str(o).startswith(str(LADERR_NS)):
                continue
            class_name = str(o).replace(str(LADERR_NS), "")
            class_counts[class_name] = class_counts.get(class_name, 0) + 1
        return dict(sorted(class_counts.items(), key=lambda item: item[1], reverse=True))

    @staticmethod
    def _create_bar_chart(data: dict, output_path: str):
        df = pd.DataFrame(list(data.items()), columns=["Class", "Count"])
        df = df.sort_values(by="Count", ascending=True)

        plt.figure(figsize=(10, 6))
        plt.barh(df["Class"], df["Count"])
        plt.xlabel("Instance Count")
        plt.ylabel("LaDeRR Class")
        plt.title("Instances per LaDeRR Class")
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    @staticmethod
    def calculate_resilience_metrics(graph: Graph) -> dict:
        vulnerabilities = set(graph.subjects(RDF.type, LADERR_NS.Vulnerability))
        disabled = LADERR_NS.disabled
        exploits = LADERR_NS.exploits
        state = LADERR_NS.state

        count_total = len(vulnerabilities)
        count_disabled_no_exploit = 0
        count_disabled_with_exploit = 0
        count_enabled_no_exploit = 0

        for v in vulnerabilities:
            is_disabled = (v, state, disabled) in graph
            has_exploit = bool(list(graph.subjects(exploits, v)))

            if is_disabled and not has_exploit:
                count_disabled_no_exploit += 1
            elif is_disabled and has_exploit:
                count_disabled_with_exploit += 1
            elif not is_disabled and not has_exploit:
                count_enabled_no_exploit += 1

        resilience_numerator = (
            count_disabled_no_exploit +
            count_disabled_with_exploit +
            count_enabled_no_exploit
        )
        resilience_index = resilience_numerator / count_total if count_total > 0 else 0.0
        vulnerability_index = 1 - resilience_index

        return {
            "resilience_index": round(resilience_index, 4),
            "vulnerability_index": round(vulnerability_index, 4),
            "total_vulnerabilities": count_total,
            "resilient_vulnerabilities": resilience_numerator,
        }

    @staticmethod
    def generate_pdf_report(graph: Graph, output_path: str = "laderr_class_report.pdf"):
        data = ReportGenerator.count_laderr_classes(graph)
        metrics = ReportGenerator.calculate_resilience_metrics(graph)
        temp_image_path = tempfile.mktemp(suffix=".png")
        ReportGenerator._create_bar_chart(data, temp_image_path)

        c = canvas.Canvas(output_path, pagesize=A4)
        width, height = A4

        # Title
        c.setFont("Helvetica-Bold", 18)
        c.drawString(2 * cm, height - 2 * cm, "LaDeRR Class Instance Report")

        # Class Table
        c.setFont("Helvetica-Bold", 12)
        c.drawString(2 * cm, height - 3.5 * cm, "Instances per Class:")
        c.setFont("Helvetica", 11)

        y = height - 4.3 * cm
        for cls, count in data.items():
            c.drawString(2 * cm, y, f"{cls}: {count}")
            y -= 0.5 * cm
            if y < 4 * cm:
                c.showPage()
                y = height - 2 * cm

        # Resilience Index Section
        y -= 1 * cm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(2 * cm, y, "Resilience Metrics:")
        y -= 0.6 * cm
        c.setFont("Helvetica", 11)
        c.drawString(2 * cm, y, f"Total Vulnerabilities: {metrics['total_vulnerabilities']}")
        y -= 0.4 * cm
        c.drawString(2 * cm, y, f"Resilient Vulnerabilities: {metrics['resilient_vulnerabilities']}")
        y -= 0.4 * cm
        c.drawString(2 * cm, y, f"Resilience Index: {metrics['resilience_index']:.4f}")
        y -= 0.4 * cm
        c.drawString(2 * cm, y, f"Vulnerability Index: {metrics['vulnerability_index']:.4f}")

        # Add chart at the bottom of page or on new page
        if y < 10 * cm:
            c.showPage()
            y = height - 2 * cm
        c.drawImage(temp_image_path, 3 * cm, 2 * cm, width - 6 * cm, 12 * cm, preserveAspectRatio=True)
        c.save()

        os.remove(temp_image_path)
