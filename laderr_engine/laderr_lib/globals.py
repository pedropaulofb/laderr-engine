from pathlib import Path

from rdflib import Namespace

# Automatically detect the root based on this file's location
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # goes from laderr_lib → laderr_engine → project root

LADERR_VOCABULARY_PATH = BASE_DIR / "resources" / "laderr-vocabulary-v0.8.3.ttl"
SHACL_FILES_PATH = BASE_DIR / "resources" / "shapes"

LADERR_NS = Namespace("https://w3id.org/laderr#")
VERBOSE = True
