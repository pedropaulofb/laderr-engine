from icecream import ic

from laderr_engine.laderr_lib import Laderr
from laderr_engine.laderr_lib.services.graph import GraphHandler
from laderr_engine.laderr_lib.services.report import ReportGenerator

# test_num = "P"
#
# Laderr.process_specification(f"examples/example_doc_{test_num}_in.toml",
#                              f"examples/example_doc_{test_num}/example_doc_{test_num}_out")

graph = GraphHandler.create_laderr_graph("examples/example_doc_P_in.toml")

graph_dict = GraphHandler.split_graph_by_scenario(graph)
for key in graph_dict.keys():
    ic(key)
    ic(graph_dict[key].serialize())

# ReportGenerator.generate_pdf_report(graph)