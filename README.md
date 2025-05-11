# LaDeRR Engine

<p align="center"><img src="https://raw.githubusercontent.com/pedropaulofb/laderr-lib/main/resources/laderr-engine-logo.png" width="500" alt="LaDeRR Engine logo"></p>

The **LaDeRR Engine** is a Python-based processing utility designed for the [LaDeRR (Language for Describing Risk and Resilience)](https://github.com/pedropaulofb/laderr) specification. It provides functionalities to convert LaDeRR specifications into RDF graphs, perform SHACL-based validations, apply reasoning to enrich data, generate visualizations, and produce comprehensive reports.

For a complete description of the LaDeRR language, please refer to the [LaDeRR User Guide](https://github.com/pedropaulofb/laderr/blob/main/documentation/laderr_user_guide.md).

## Installation

1. Clone the repository:

```bash
git clone https://github.com/pedropaulofb/laderr-engine.git
cd laderr-engine
```

2. Create and activate a virtual environment (optional but recommended):

```bash
python -m venv venv
# For Windows:
venv\Scripts\activate
# For Linux/Mac:
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

The LaDeRR Engine can be used either as a standalone script or integrated as a library in your Python projects.

### As a Script

Run the following command, specifying your input TOML file and an output base path (used as prefix for generated files):

```bash
python laderr_engine.py <input_file> <output_base>
```

**Example:**

```bash
python laderr_engine.py example\example_doc_in.toml example\output\example_doc_out
```

### As a Library

You can integrate the LaDeRR Engine functionalities directly into your Python projects by importing methods from the `Laderr` utility class, located in the module `laderr_engine.laderr_lib.laderr`.

This class provides static methods to:

- Convert LaDeRR specifications into RDF graphs.
- Validate RDF graphs using SHACL constraints.
- Apply reasoning to enrich RDF data.
- Generate visualizations and reports.
- Save RDF graphs and processed specifications.

Below is an example demonstrating how to process a LaDeRR specification within your Python code:

```python
from laderr_engine.laderr_lib import Laderr

# Specify the input LaDeRR specification and output base path
input_spec_path = "path/to/your/specification.toml"
output_file_base = "path/to/output/base_name"

# Process the specification using default settings
try:
    Laderr.process_specification(
        input_spec_path=input_spec_path,
        output_file_base=output_file_base,
        verbose=True  # Set to False to suppress detailed logging
    )
except Exception as e:
    print(f"Error processing LaDeRR specification: {e}")
```

For detailed usage, additional configurations, and other available methods, refer directly to the docstrings provided within the `Laderr` class methods.

## Contributing

Contributions are welcome! If you would like to contribute, please fork the repository and submit a pull request.

## Author

The LaDeRR Engine is developed and maintained by:

- Pedro Paulo Favato Barcelos [[GitHub](https://github.com/pedropaulofb)] [[LinkedIn](https://www.linkedin.com/in/pedro-paulo-favato-barcelos/)]

Feel free to reach out using the provided links. For inquiries, contributions, or to report any issues, you can [open a new issue](https://github.com/pedropaulofb/laderr-lib/issues/new) on this repository.
