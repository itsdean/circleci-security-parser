import os
from pathlib import Path

class Loader:

    def __init__(self, output_wrapper):
        self.output_wrapper = output_wrapper
        self.loaded_files = list()


    def elements(self):
        return


    def load_from_folder(self, folder):

        # # Create an empty list - this list will contain all of the File objects we create
        self.loaded_files = list()

        self.output_wrapper.set_title("Loading from: " + folder)
        
        # Get the full path of the folder
        folder_path = os.path.abspath(folder)

        # Create open file objects for all JSON files in the input folder
        # and store them in the files list object
        for filename in Path(folder_path).glob("**/results_*.json"):
            file_object = open(str(filename), "r")
            self.loaded_files.append(file_object)

        loaded_files_size = len(self.loaded_files)

        if loaded_files_size > 0:

            # Output any files!
            if loaded_files_size >= 1:
                self.output_wrapper.add(str(loaded_files_size) + " supported files were found!")
            else:
                self.output_wrapper.add("1 supported file was found!")

            for element in self.loaded_files:
                # Get just the filename from the File object and output it
                loaded_file_name = os.path.basename(element.name)
                self.output_wrapper.add("- " + loaded_file_name)

            self.output_wrapper.flush(verbose=True)
            return self.loaded_files

        else:

            self.output_wrapper.flush(verbose=True)
            return 0

        
