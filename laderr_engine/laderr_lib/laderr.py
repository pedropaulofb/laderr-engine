"""
LaDeRR Library Module

This module provides a collection of static methods to operate on RDF data, perform validation, apply reasoning,
and generate visualizations for LaDeRR (Language for Describing Risk and Resilience) specifications.

### Core Functionalities:
- Convert a LaDeRR specification into an RDF graph.
- Validate RDF graphs using SHACL constraints.
- Apply reasoning to enrich RDF data.
- Save processed graphs and specifications to files.
- Generate graphical representations of LaDeRR models.

All methods are **static** within the `Laderr` class, allowing direct access without instantiation.
"""
from loguru import logger
from rdflib import Graph
import os

from laderr_engine.laderr_lib.services.graph import GraphHandler
from laderr_engine.laderr_lib.services.reasoning import ReasoningHandler
from laderr_engine.laderr_lib.services.specification import SpecificationHandler
from laderr_engine.laderr_lib.services.validation import ValidationHandler
from laderr_engine.laderr_lib.services.visualization import GraphCreator


class Laderr:
    """
    LaDeRR Processing Utility Class

    Provides core functionalities for handling LaDeRR specifications, including RDF graph processing,
    validation, reasoning execution, serialization, and visualization.

    **Key Functionalities:**
    - Convert LaDeRR specifications into RDF graphs.
    - Validate RDF graphs using SHACL constraints.
    - Apply reasoning to enrich RDF data.
    - Save RDF graphs and processed specifications to structured files.
    - Generate graphical representations of LaDeRR models.
    """

    def __init__(self):
        raise TypeError(f"{self.__class__.__name__} is a utility class and cannot be instantiated.")

    @staticmethod
    def load_spec_to_graph(input_spec_path: str, verbose: bool = False) -> Graph:
        """
        Loads a LaDeRR specification file and converts it into an RDF graph.

        :param input_spec_path: Path to the LaDeRR specification file.
        :param verbose: Whether to log success messages upon completion.
        :return: RDF graph containing the parsed LaDeRR specification.
        """
        laderr_graph = GraphHandler.create_laderr_graph(input_spec_path)
        if verbose:
            logger.success(f"Graph successfully created for: {input_spec_path}")
        return laderr_graph

    @staticmethod
    def validate_graph(laderr_graph: Graph, verbose: bool = False) -> tuple[bool, str, Graph]:
        """
        Validates an RDF graph using SHACL constraints.

        :param laderr_graph: The RDF graph to validate.
        :param verbose: Whether to log validation results.
        :return: Tuple containing (conforms, validation report text, validation report graph).
        """
        conforms, report_text, report_graph = ValidationHandler.validate_laderr_graph(laderr_graph)
        if verbose:
            status = "PASSED" if conforms else "FAILED"
            logger.info(f"Validation {status}: {report_text}")
        return conforms, report_text, report_graph

    @staticmethod
    def run_reasoning_on_graph(laderr_graph: Graph, verbose: bool = False) -> Graph:
        """
        Executes reasoning on an RDF graph and returns the updated graph.

        :param laderr_graph: The RDF graph to apply reasoning on.
        :param verbose: Whether to log messages.
        :return: The RDF graph with reasoning applied.
        """
        ReasoningHandler.execute(laderr_graph)
        if verbose:
            logger.success("Reasoning successfully applied to the graph.")
        return laderr_graph

    @staticmethod
    def save_graph(laderr_graph: Graph, output_file_path: str, verbose: bool = True) -> None:
        """
        Saves an RDF graph to a specified file.

        :param laderr_graph: The RDF graph to save.
        :param output_file_path: The path where the graph should be saved.
        :param verbose: Whether to log success messages.
        """
        GraphHandler.save_graph(laderr_graph, output_file_path)
        if verbose:
            logger.success(f"Graph successfully saved to: {output_file_path}")

    @staticmethod
    def save_visualization_from_graph(laderr_graph: Graph, output_file_path: str, verbose: bool = False) -> None:
        """
        Generates a visualization from an RDF graph and saves it to a file.

        :param laderr_graph: The RDF graph to visualize.
        :param output_file_path: Path where the visualization should be saved.
        :param verbose: Whether to log messages.
        """
        GraphCreator.create_graph_visualization(laderr_graph, output_file_path)
        if verbose:
            logger.success(f"Visualization successfully saved to {output_file_path}")

    @staticmethod
    def process_specification(
            input_spec_path: str,
            output_file_path: str,
            validate_pre: bool = True,
            validate_post: bool = True,
            exec_inferences: bool = True,
            save_graph_pre: bool = True,
            save_graph_post: bool = True,
            save_visualization_pre: bool = True,
            save_visualization_post: bool = True,
            verbose: bool = True
            # TODO: Set save_graph_pre, save_graph_post, save_visualization_pre, and verbose with default False
    ) -> None:
        """
        Loads, processes, and optionally validates and enriches a LaDeRR specification,
        then saves the resulting specification and optionally its graph representation and visualization.

        :param input_spec_path: Path to the input LaDeRR specification file.
        :param output_file_path: Path where the processed specification should be saved.
        :param validate_pre: Whether to validate before reasoning.
        :param validate_post: Whether to validate after reasoning.
        :param exec_inferences: Whether to apply reasoning.
        :param save_graph_pre: Whether to save the graph before processing.
        :param save_graph_post: Whether to save the processed graph.
        :param save_visualization_pre: Whether to save the visualization before processing.
        :param save_visualization_post: Whether to save the visualization after processing.
        :param verbose: Whether to log messages.
        """
        output_base = os.path.splitext(output_file_path)[0]
        laderr_graph = GraphHandler.create_laderr_graph(input_spec_path)

        if save_graph_pre:
            GraphHandler.save_graph(laderr_graph, f"{output_base}_pre.ttl")
            if verbose:
                logger.success(f"Pre-processed graph saved to {output_base}_pre.ttl")

        if save_visualization_pre:
            GraphCreator.create_graph_visualization(laderr_graph, f"{output_base}_pre.png")
            if verbose:
                logger.success(f"Pre-processed visualization saved to {output_base}_pre.png")

        if validate_pre:
            Laderr.validate_graph(laderr_graph, verbose)
        if exec_inferences:
            laderr_graph = Laderr.run_reasoning_on_graph(laderr_graph, verbose)
        if validate_post:
            Laderr.validate_graph(laderr_graph, verbose)

        if save_graph_post:
            GraphHandler.save_graph(laderr_graph, f"{output_base}.ttl")
            if verbose:
                logger.success(f"Processed graph saved to {output_base}.ttl")

        if save_visualization_post:
            GraphCreator.create_graph_visualization(laderr_graph, f"{output_base}.png")
            if verbose:
                logger.success(f"Processed visualization saved to {output_base}.png")

        SpecificationHandler.write_specification(laderr_graph, output_file_path)
        if verbose:
            logger.success(f"Processed specification successfully saved to: {output_file_path}")

