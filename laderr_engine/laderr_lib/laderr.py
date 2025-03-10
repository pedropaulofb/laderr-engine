"""
LaDeRR Library Module

This module provides a collection of static methods to operate on RDF data,
perform optional SHACL validation, apply reasoning, and generate visualizations
for LaDeRR (Language for Describing Risk and Resilience) specifications.

### Core Functionalities:
- Convert a LaDeRR specification into an RDF graph.
- Validate RDF graphs using SHACL constraints (optional, logs errors and proceeds).
- Apply reasoning to enrich RDF data (optional).
- Save processed graphs and specifications to files.
- Generate graphical representations of LaDeRR models.

All methods are **static** within the `Laderr` class, allowing direct access
without instantiation.

### Dependencies:
- `rdflib` for RDF graph processing.
- `loguru` for structured logging.
- `laderr_engine.laderr_lib.services.*` for handling graphs, validation, reasoning,
  specification processing, and visualization.
"""

from loguru import logger
from rdflib import Graph

from laderr_engine.laderr_lib.services.graph import GraphHandler
from laderr_engine.laderr_lib.services.reasoning import ReasoningHandler
from laderr_engine.laderr_lib.services.specification import SpecificationHandler, VERBOSE
from laderr_engine.laderr_lib.services.validation import ValidationHandler
from laderr_engine.laderr_lib.services.visualization import GraphCreator


class Laderr:
    """
    LaDeRR Processing Utility Class

    This class provides **static methods** for handling LaDeRR specifications,
    including RDF graph creation, validation, inference execution, specification
    serialization, and visualization generation.

    ### Key Functionalities:
    - Convert LaDeRR specifications into RDF graphs.
    - Perform optional SHACL validation before and after inference.
    - Apply reasoning to enrich RDF data with additional relationships.
    - Save RDF graphs and processed specifications to structured files.
    - Generate graphical representations of LaDeRR models.

    **Usage Example:**
    ```python
    graph = Laderr.load_spec_to_graph("spec.toml", validate=True, exec_inferences=True)
    Laderr.save_spec_from_graph(graph, "output_spec.toml", verbose=True)
    ```

    **Note:**
    - This class **cannot be instantiated**.
    - All methods should be called **directly on the class**.
    """

    def __init__(self):
        """
        Prevents instantiation of the `Laderr` class.

        This class is a static utility class and is not meant to be instantiated.
        Any attempt to create an instance will result in a `TypeError`.

        **Example:**
        ```python
        laderr_instance = Laderr()  # This will raise an error.
        ```

        To use the class, call its static methods directly:
        ```python
        graph = Laderr.load_spec_to_graph("spec.toml")
        ```

        :raises TypeError: Always raises an error to prevent instantiation.
        """
        raise TypeError(f"{self.__class__.__name__} is a utility class and cannot be instantiated.")

    @staticmethod
    def load_spec_to_graph(
            input_spec_path: str,
            verbose: bool = False,
            validate: bool = True,
            validate_post: bool = True,
            exec_inferences: bool = True
    ) -> Graph:
        """
        Loads a LaDeRR specification file, validates it (if enabled), applies reasoning
        (if enabled), and converts it into an RDF graph.

        **Process Overview:**
        1. Loads the LaDeRR specification from the given file.
        2. Performs **optional validation** before applying reasoning.
        3. Applies **optional reasoning** to enrich the graph.
        4. Performs **optional validation** after reasoning.
        5. Logs messages and returns the processed RDF graph.

        **Note:**
        - If validation fails, errors are **logged**, but execution proceeds.

        :param input_spec_path: Path to the LaDeRR specification file.
        :type input_spec_path: str
        :param verbose: Whether to log success messages upon completion.
        :type verbose: bool
        :param validate: Whether to validate the graph before applying reasoning.
        :type validate: bool
        :param validate_post: Whether to validate the graph after applying reasoning.
        :type validate_post: bool
        :param exec_inferences: Whether to apply reasoning to enrich the RDF graph.
        :type exec_inferences: bool
        :return: A single RDF graph containing the parsed and processed LaDeRR specification.
        :rtype: Graph
        """
        laderr_graph = GraphHandler.create_laderr_graph(input_spec_path)

        Laderr._validate_graph_if_enabled(laderr_graph, validate, verbose, "Pre-validation")

        Laderr._apply_reasoning_if_enabled(laderr_graph, exec_inferences, verbose)

        Laderr._validate_graph_if_enabled(laderr_graph, validate_post, verbose, "Post-validation")

        if verbose:
            logger.success(f"Graph with LaDeRR specification successfully created for: {input_spec_path}")

        return laderr_graph

    @staticmethod
    def validate_graph(laderr_graph: Graph, verbose: bool = False) -> tuple[bool, str, Graph]:
        """
        Validates an RDF graph using SHACL constraints.

        This method checks whether the provided RDF graph conforms to
        SHACL schema rules defined for LaDeRR specifications.

        **Validation Process:**
        - The method applies SHACL validation rules to the given RDF graph.
        - If validation **fails**, errors are **logged**, but execution proceeds.

        **Return Values:**
        - **conforms (bool):** `True` if the graph conforms to SHACL constraints, `False` otherwise.
        - **report_text (str):** Detailed validation results as a string.
        - **report_graph (Graph):** RDF graph representing the SHACL validation report.

        :param laderr_graph: The RDF graph to validate.
        :type laderr_graph: Graph
        :param verbose: Whether to log validation results.
        :type verbose: bool
        :return: A tuple containing (conforms, report_text, report_graph).
        :rtype: tuple[bool, str, Graph]
        """
        conforms, report_text, report_graph = ValidationHandler.validate_laderr_graph(laderr_graph)

        if verbose:
            status = "PASSED" if conforms else "FAILED"
            logger.info(f"Validation {status}: {report_text}")

        return conforms, report_text, report_graph

    @staticmethod
    def validate_spec(input_spec_path: str, verbose: bool = False) -> tuple[bool, str, Graph]:
        """
        Loads a LaDeRR specification file and validates it using SHACL constraints.

        This method reads the specification file, converts it into an RDF graph,
        and checks whether it conforms to SHACL validation rules.

        :param input_spec_path: Path to the LaDeRR specification file.
        :type input_spec_path: str
        :param verbose: If True, logs validation results.
        :type verbose: bool
        :return: A tuple containing:
            - A boolean indicating whether the graph conforms to SHACL constraints.
            - A string containing detailed validation results.
            - A graph representing the SHACL validation report.
        :rtype: tuple[bool, str, Graph]
        """
        laderr_graph = GraphHandler.create_laderr_graph(input_spec_path)
        conforms, report_text, report_graph = ValidationHandler.validate_laderr_graph(laderr_graph)

        if verbose:
            validation_status = "PASSED" if conforms else "FAILED"
            logger.info(f"Validation {validation_status}: {report_text}")

        return conforms, report_text, report_graph

    @staticmethod
    def save_graph(
            laderr_graph: Graph,
            output_file_path: str,
            validate: bool = True,
            validate_post: bool = True,
            exec_inferences: bool = True,
            verbose: bool = True
    ) -> None:
        """
        Saves an RDF graph to a specified file, with optional validation and reasoning.

        :param laderr_graph: The RDF graph to save.
        :type laderr_graph: Graph
        :param output_file_path: The path where the graph should be saved.
        :type output_file_path: str
        :param validate: If True, validates the graph before reasoning.
        :type validate: bool
        :param validate_post: If True, validates the graph after reasoning.
        :type validate_post: bool
        :param exec_inferences: If True, applies reasoning to the graph.
        :type exec_inferences: bool
        :param verbose: If True, logs success messages.
        :type verbose: bool
        """
        Laderr._validate_graph_if_enabled(laderr_graph, validate, verbose, "Pre-validation")

        Laderr._apply_reasoning_if_enabled(laderr_graph, exec_inferences, verbose)

        Laderr._validate_graph_if_enabled(laderr_graph, validate_post, verbose, "Post-validation")

        GraphHandler.save_graph(laderr_graph, output_file_path)

        if verbose:
            logger.success(f"Graph successfully saved to: {output_file_path}")

    @staticmethod
    def save_spec_from_graph(
            laderr_graph: Graph,
            output_file_path: str,
            validate: bool = True,
            validate_post: bool = True,
            exec_inferences: bool = True,
            verbose: bool = True
    ) -> None:
        """
        Saves an RDF graph as a LaDeRR specification file, with optional validation and reasoning.

        :param laderr_graph: The RDF graph to save as a specification.
        :type laderr_graph: Graph
        :param output_file_path: The path where the specification file should be saved.
        :type output_file_path: str
        :param validate: If True, validates the graph before reasoning.
        :type validate: bool
        :param validate_post: If True, validates the graph after reasoning.
        :type validate_post: bool
        :param exec_inferences: If True, applies reasoning to the graph.
        :type exec_inferences: bool
        :param verbose: If True, logs success messages.
        :type verbose: bool
        """
        Laderr._validate_graph_if_enabled(laderr_graph, validate, verbose, "Pre-validation")

        Laderr._apply_reasoning_if_enabled(laderr_graph, exec_inferences, verbose)

        Laderr._validate_graph_if_enabled(laderr_graph, validate_post, verbose, "Post-validation")

        SpecificationHandler.write_specification(laderr_graph, output_file_path)

        if verbose:
            logger.success(f"LaDeRR specification successfully saved to: {output_file_path}")

    @staticmethod
    def save_spec_from_spec(
            input_spec_path: str,
            output_file_path: str,
            validate: bool = True,
            validate_post: bool = True,
            exec_inferences: bool = True,
            verbose: bool = False
    ) -> None:
        """
        Loads a LaDeRR specification file, validates it (if enabled), applies reasoning
        (if enabled), performs post-validation (if enabled), and saves the resulting specification.

        **Process Order:**
        1. **Load** the specification as an RDF graph.
        2. **Validate** before inference (if enabled).
        3. **Apply reasoning** to enrich the graph (if enabled).
        4. **Validate** after inference (if enabled).
        5. **Save** the processed specification.

        **Note:**
        - Validation failures are **logged**, but execution proceeds.

        :param input_spec_path: Path to the input LaDeRR specification file.
        :type input_spec_path: str
        :param output_file_path: Path where the processed specification should be saved.
        :type output_file_path: str
        :param validate: Whether to validate before inference.
        :type validate: bool
        :param validate_post: Whether to validate after inference.
        :type validate_post: bool
        :param exec_inferences: Whether to apply reasoning.
        :type exec_inferences: bool
        :param verbose: Whether to log messages.
        :type verbose: bool
        """
        # Load the specification as an RDF graph
        laderr_graph = GraphHandler.create_laderr_graph(input_spec_path)

        Laderr._validate_graph_if_enabled(laderr_graph, validate, verbose, "Pre-validation")

        Laderr._apply_reasoning_if_enabled(laderr_graph, exec_inferences, verbose)

        Laderr._validate_graph_if_enabled(laderr_graph, validate_post, verbose, "Post-validation")

        SpecificationHandler.write_specification(laderr_graph, output_file_path)

        if verbose:
            logger.success(f"Processed specification successfully saved to: {output_file_path}")

    @staticmethod
    def save_visualization_from_graph(
            laderr_graph: Graph,
            output_file_path: str,
            validate: bool = True,
            validate_post: bool = True,
            exec_inferences: bool = True,
            verbose: bool = False
    ) -> None:
        """
        Validates an RDF graph (if enabled), applies inference (if enabled),
        performs post-validation (if enabled), and generates a visualization.

        :param laderr_graph: The RDF graph to visualize.
        :type laderr_graph: Graph
        :param output_file_path: Path where the visualization should be saved.
        :type output_file_path: str
        :param validate: If True, performs SHACL validation before inference.
        :type validate: bool
        :param validate_post: If True, performs SHACL validation after inference.
        :type validate_post: bool
        :param exec_inferences: If True, applies reasoning to enrich the graph.
        :type exec_inferences: bool
        :param verbose: If True, logs messages about the process.
        :type verbose: bool
        """
        Laderr._validate_graph_if_enabled(laderr_graph, validate, verbose, "Pre-validation")

        Laderr._apply_reasoning_if_enabled(laderr_graph, exec_inferences, verbose)

        Laderr._validate_graph_if_enabled(laderr_graph, validate_post, verbose, "Post-validation")

        GraphCreator.create_graph_visualization(laderr_graph, output_file_path)

        if verbose:
            logger.success(f"Visualization successfully saved to {output_file_path}")

    @staticmethod
    def save_visualization_from_spec(
            input_spec_path: str,
            output_file_path: str,
            validate: bool = True,
            validate_post: bool = True,
            exec_inferences: bool = True,
            verbose: bool = False
    ) -> None:
        """
        Loads a LaDeRR specification file, validates it (if enabled), applies inference (if enabled),
        performs post-validation (if enabled), and generates a visualization.

        :param input_spec_path: Path to the input LaDeRR specification file.
        :type input_spec_path: str
        :param output_file_path: Path where the visualization should be saved.
        :type output_file_path: str
        :param validate: If True, performs SHACL validation before inference.
        :type validate: bool
        :param validate_post: If True, performs SHACL validation after inference.
        :type validate_post: bool
        :param exec_inferences: If True, applies reasoning to enrich the graph.
        :type exec_inferences: bool
        :param verbose: If True, logs messages about the process.
        :type verbose: bool
        """
        # Load the specification as an RDF graph
        laderr_graph = GraphHandler.create_laderr_graph(input_spec_path)

        Laderr._validate_graph_if_enabled(laderr_graph, validate, verbose, "Pre-validation")

        Laderr._apply_reasoning_if_enabled(laderr_graph, exec_inferences, verbose)

        Laderr._validate_graph_if_enabled(laderr_graph, validate_post, verbose, "Post-validation")

        GraphCreator.create_graph_visualization(laderr_graph, output_file_path)

        if verbose:
            logger.success(f"Visualization successfully saved to {output_file_path}")

    @staticmethod
    def _validate_graph_if_enabled(
            laderr_graph: Graph,
            validate: bool,
            verbose: bool,
            validation_stage: str = "Validation"
    ) -> bool:
        """
        Performs SHACL validation on the RDF graph if validation is enabled.

        :param laderr_graph: The RDF graph to validate.
        :type laderr_graph: Graph
        :param validate: If True, performs validation.
        :type validate: bool
        :param verbose: If True, logs validation results.
        :type verbose: bool
        :param validation_stage: Descriptive name of the validation stage (e.g., "Pre-validation", "Post-validation").
        :type validation_stage: str
        :return: True if the graph conforms to SHACL constraints, False otherwise.
        :rtype: bool
        """
        if not validate:
            return True  # Skip validation if disabled

        conforms, report_text, _ = ValidationHandler.validate_laderr_graph(laderr_graph)

        if verbose:
            status = "PASSED" if conforms else "FAILED"
            logger.info(f"{validation_stage} {status}: {report_text}")

        if not conforms:
            logger.error(f"{validation_stage} failed. Proceeding anyway.")

        return conforms

    @staticmethod
    def _apply_reasoning_if_enabled(laderr_graph: Graph, exec_inferences: bool, verbose: bool) -> None:
        """
        Applies reasoning (inference) to the RDF graph if enabled.

        :param laderr_graph: The RDF graph to apply reasoning on.
        :type laderr_graph: Graph
        :param exec_inferences: If True, applies reasoning.
        :type exec_inferences: bool
        :param verbose: If True, logs success message.
        :type verbose: bool
        """
        if exec_inferences:
            ReasoningHandler.execute(laderr_graph)
            if verbose:
                logger.info("Inference successfully applied to the graph.")
