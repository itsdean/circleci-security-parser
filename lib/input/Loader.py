import os
import sys

from pathlib import Path

def load_from_folder(logger, folder):
    l = logger

    # Create an empty list - this will contain all of the File objects we load
    loaded_files = list()

    # Get the full path of the folder
    path = os.path.abspath(folder)
    l.info(f"Attempting to load files from {path}")

    # Create a File object for each JSON file in the folder, storing them in loaded_files
    for filename in Path(path).glob("**/results_*.json"):
        tool_output = open(str(filename), "r", encoding="utf-8")
        loaded_files.append(tool_output)

    if len(loaded_files) > 0:
        l.info(f"Loaded {len(loaded_files)} supported file(s)")
        for filename in loaded_files:
            l.debug(f"> {os.path.basename(filename.name)}")
        print()
    else:
        l.critical("No supported files were found - did you target the right directory?")
        sys.exit(-1)

    return loaded_files
