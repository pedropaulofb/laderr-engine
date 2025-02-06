from icecream import ic
from rdflib import Namespace, Graph

from laderr_engine.laderr_lib import Laderr


class HandlerValidator:

    @classmethod
    def validate_specification(cls, laderr_file_path: str):
        # Syntactical validation
        spec_metadata_dict, spec_data_dict = Laderr._read_specification(laderr_file_path)

        # Semantic validation
        spec_metadata_graph = Laderr._load_spec_metadata(spec_metadata_dict)
        spec_data_graph = Laderr._load_spec_data(spec_metadata_dict, spec_data_dict)

        # Combine graphs
        unified_graph = Graph()
        unified_graph += spec_metadata_graph
        unified_graph += spec_data_graph

        Laderr.write_specification(spec_metadata_graph, spec_data_graph, "./test_output.toml")

        # Combine instances with Schema for correct SHACL evaluation
        laderr_schema = Laderr._load_schema()
        validation_graph = Graph()
        validation_graph += unified_graph
        validation_graph += laderr_schema

        # Bind namespaces in the unified graph
        base_uri = cls._validate_base_uri(spec_metadata_dict)
        unified_graph.bind("", Namespace(base_uri))  # Bind `:` to the base URI
        unified_graph.bind("laderr", cls.LADER_NS)  # Bind `laderr:` to the schema namespace

        ic(len(spec_metadata_graph), len(spec_data_graph), len(unified_graph), len(laderr_schema),
           len(validation_graph))

        conforms, _, report_text = Laderr._validate_with_shacl(validation_graph)
        Laderr._report_validation_result(conforms, report_text)
        Laderr._save_graph(unified_graph, "./result.ttl")
        return conforms

    def validate_graph(self):
        pass
