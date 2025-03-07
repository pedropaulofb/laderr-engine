import os

from loguru import logger


def find_file_by_partial_name(folder_path: str, partial_name: str) -> str:
    """
    Search for a file in the given folder that contains the specified partial name.

    Args:
        folder_path (str): The complete path to the folder.
        partial_name (str): The string to search for in file names.

    Returns:
        str: The full path of the first matching file, or an empty string if no match is found.
    """
    if not os.path.isdir(folder_path):
        raise ValueError(f"The folder path '{folder_path}' does not exist or is not a directory.")

    for filename in os.listdir(folder_path):
        if partial_name in filename:
            return os.path.join(folder_path, filename)

    # No file found matching the criteria
    logger.warning("No file found matching the criteria.")
    return ""
