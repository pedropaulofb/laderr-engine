import os
import tempfile
import tomllib

import pytest

from laderr_engine.laderr_lib.services.specification import SpecificationHandler


def generate_test_cases_from_folder(folder_path: str):
    """
    Generator that yields file paths for all TOML files in the specified folder.

    :param folder_path: Path to the folder containing TOML files.
    :type folder_path: str
    :yield: Paths to individual TOML files.
    :rtype: Iterator[str]
    """
    for file_name in os.listdir(folder_path):
        if file_name.endswith(".toml"):
            yield os.path.join(folder_path, file_name)


@pytest.fixture
def temp_toml_file():
    """
    Provides a temporary TOML file that can be written to.
    Ensures cleanup after test.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml", mode="w") as temp_file:
        yield temp_file.name


@pytest.mark.parametrize("toml_content, expected_metadata_defaults", [  # Case 1: Metadata is completely empty
    ({}, {"scenario": "operational", "baseUri": "https://laderr.laderr#"}),
    # Case 2: Metadata has some fields but is missing defaults
    ({"title": "My Spec", "createdOn": "2025-03-06T12:00:00Z"},
     {"title": "My Spec", "createdOn": "2025-03-06T12:00:00Z", "scenario": "operational",
      "baseUri": "https://laderr.laderr#"}),  # Case 3: Metadata with all fields present (no defaults applied)
    ({"title": "My Spec", "scenario": "incident", "baseUri": "https://custom.uri#", "createdBy": ["Alice"],
      "createdOn": "2025-03-06T12:00:00Z"},
     {"title": "My Spec", "scenario": "incident", "baseUri": "https://custom.uri#", "createdBy": ["Alice"],
      "createdOn": "2025-03-06T12:00:00Z"})])
def test_metadata_defaults(temp_toml_file, toml_content, expected_metadata_defaults):
    """
    Tests that metadata defaults are correctly applied by read_specification.
    """
    with open(temp_toml_file, "w", encoding="utf-8") as f:
        f.write(dict_to_toml_str(toml_content))

    metadata, _ = SpecificationHandler.read_specification(temp_toml_file)

    for key, expected_value in expected_metadata_defaults.items():
        assert metadata[key] == expected_value


@pytest.mark.parametrize("construct_type, instance_key, initial_properties, expected_properties",
                         [("Entity", "riverford", {}, {"id": "riverford", "label": "riverford"}), (
                                 "Capability", "flood_control", {},
                                 {"id": "flood_control", "label": "flood_control", "status": "enabled"}), (
                                  "Vulnerability", "weak_levee", {},
                                  {"id": "weak_levee", "label": "weak_levee", "status": "enabled"}), (
                                  "Capability", "custom_capability",
                                  {"id": "custom_capability", "label": "Custom Label", "status": "disabled"},
                                  {"id": "custom_capability", "label": "Custom Label", "status": "disabled"})])
def test_construct_defaults(temp_toml_file, construct_type, instance_key, initial_properties, expected_properties):
    """
    Tests that defaults for constructs (id, label, status) are correctly applied by read_specification.
    """

    # Flattened representation - the parser expects this format:
    section_key = f"{construct_type}.{instance_key}"

    toml_content = {section_key: initial_properties}

    with open(temp_toml_file, "w", encoding="utf-8") as f:
        f.write(dict_to_toml_str(toml_content))

    _, data = SpecificationHandler.read_specification(temp_toml_file)

    assert data[construct_type][instance_key] == expected_properties


@pytest.mark.parametrize("created_by_value, expected_normalized",
                         [("Alice", ["Alice"]), (["Alice", "Bob"], ["Alice", "Bob"])])
def test_created_by_normalization(temp_toml_file, created_by_value, expected_normalized):
    """
    Tests that createdBy is correctly normalized to a list.
    """
    toml_content = {"createdBy": created_by_value}

    with open(temp_toml_file, "w", encoding="utf-8") as f:
        f.write(dict_to_toml_str(toml_content))

    metadata, _ = SpecificationHandler.read_specification(temp_toml_file)

    assert metadata["createdBy"] == expected_normalized


@pytest.mark.parametrize("file_path", generate_test_cases_from_folder("test_files/invalid/syntax"))
def test_validate_syntax_errors(file_path: str) -> None:
    """
    Tests that the validate method raises TOMLDecodeError for syntactical errors in TOML files.

    :param file_path: Path to the invalid TOML file.
    :type file_path: str
    :raises AssertionError: If the expected exception is not raised.
    """
    try:
        with open(file_path, "rb") as f:
            tomllib.load(f)  # Attempt to load the TOML file
    except tomllib.TOMLDecodeError:
        # If a decode error occurs, we consider the test passed
        return

    pytest.fail(f"No TOMLDecodeError was raised for file: {file_path}")


def dict_to_toml_str(d: dict, indent_level=0) -> str:
    toml_str = ""
    indent = "    " * indent_level
    for key, value in d.items():
        if isinstance(value, dict):
            toml_str += f"{indent}[{key}]\n"
            toml_str += dict_to_toml_str(value, indent_level + 0)
        elif isinstance(value, list):
            list_str = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
            toml_str += f"{indent}{key} = [{list_str}]\n"
        elif isinstance(value, str):
            toml_str += f'{indent}{key} = "{value}"\n'
        else:
            toml_str += f"{indent}{key} = {value}\n"
    return toml_str

import logging
from loguru import logger

@pytest.fixture
def loguru_caplog(caplog):
    """ Redirect Loguru logs into `caplog`, so pytest can capture them. """
    class PropagateHandler(logging.Handler):
        def emit(self, record):
            logging.getLogger(record.name).handle(record)

    handler_id = logger.add(PropagateHandler(), level=0)
    yield caplog
    logger.remove(handler_id)


@pytest.mark.parametrize("construct_type, section_key, provided_id",
                         [("Entity", "riverford", "wrong_id"),
                          ("Capability", "flood_control", "unexpected_id")])
def test_id_conflict_warning(temp_toml_file, loguru_caplog, construct_type, section_key, provided_id):
    """
    Tests that a warning is logged if the user provides a conflicting 'id'.
    """
    loguru_caplog.clear()

    toml_content = {
        f"{construct_type}.{section_key}": {"id": provided_id}
    }

    with open(temp_toml_file, "w", encoding="utf-8") as f:
        f.write(dict_to_toml_str(toml_content))

    SpecificationHandler.read_specification(temp_toml_file)

    warning_found = any(
        f"Ignoring user-provided 'id' = '{provided_id}'" in message
        for message in loguru_caplog.text.splitlines()
    )

    assert warning_found, f"Expected warning about 'id' conflict was not found in logs for {construct_type}.{section_key}"


def test_no_unnecessary_defaults(temp_toml_file):
    """
    Tests that fully defined constructs are not modified by _apply_defaults.
    """
    toml_content = {
        "Capability.flood_control": {
            "id": "flood_control",
            "label": "Flood Control System",
            "status": "disabled"
        }
    }

    with open(temp_toml_file, "w", encoding="utf-8") as f:
        f.write(dict_to_toml_str(toml_content))

    _, data = SpecificationHandler.read_specification(temp_toml_file)

    assert data["Capability"]["flood_control"] == {
        "id": "flood_control",
        "label": "Flood Control System",
        "status": "disabled"
    }

def test_empty_specification(temp_toml_file):
    """
    Tests behavior when the specification is completely empty.
    """
    with open(temp_toml_file, "w", encoding="utf-8") as f:
        f.write("")

    metadata, data = SpecificationHandler.read_specification(temp_toml_file)

    assert metadata == {
        "scenario": "operational",
        "baseUri": "https://laderr.laderr#"
    }
    assert data == {}

def test_unrecognized_constructs_are_preserved(temp_toml_file):
    """
    Tests that unrecognized constructs are preserved in the parsed result.
    """
    toml_content = {
        "UnknownType.strange": {
            "someField": "someValue"
        }
    }

    with open(temp_toml_file, "w", encoding="utf-8") as f:
        f.write(dict_to_toml_str(toml_content))

    _, data = SpecificationHandler.read_specification(temp_toml_file)

    assert "UnknownType" in data
    assert "strange" in data["UnknownType"]
    assert data["UnknownType"]["strange"]["someField"] == "someValue"
