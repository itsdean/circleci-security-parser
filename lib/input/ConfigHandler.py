import yaml

from os import path

class ConfigHandler:


    def set_fail_threshold(self, fail_threshold):
        self.fail_threshold = fail_threshold


    def get_fail_threshold(self):
        return self.fail_threshold


    def parse(self, yaml_object):
        """
        Obtains the various fields from the yaml file. 
        """

        try:
            self.set_fail_threshold(yaml_object["fail_threshold"])
            self.output.add("- fail_threshold: " + self.get_fail_threshold())
        except TypeError:
            self.output.add("- [x] fail_threshold not found, defaulting")


    def load(self, filename):
        """
        Loads the actual file into a structure known to pyyaml.
        """

        self.output.set_title("Loading configuration from " + filename + "...")

        if path.exists(filename):

            with open(filename) as config_file:
                self.output.add("summit.yml file found!")
                yaml_object = yaml.load(config_file, Loader=yaml.FullLoader)

                self.parse(yaml_object)

        else:
            self.output.add("[x] No summit.yml file found - loading failed!")

        self.output.flush()


    def __init__(self, output_wrapper, filename="summit.yml"):

        self.output = output_wrapper

        # Define the various configuration fields
        # By default, parser builds fail if an issue with severity high or
        # above was found.
        self.fail_threshold = "high"

        # Load the configuration file
        self.load(filename)

        pass