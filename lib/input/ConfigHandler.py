import yaml

from os import path

class ConfigHandler:


    def set_fail_threshold(self, fail_threshold):
        self.fail_threshold = fail_threshold


    def get_fail_threshold(self):
        if self.fail_threshold == "":
            return "off"
        else:  
            return self.fail_threshold 

    def parse(self, yaml_object):
        """
        Obtains the various fields from the yaml file. 
        """

        if yaml_object["fail_threshold"]:
            self.set_fail_threshold(yaml_object["fail_threshold"])
            self.output.add("- fail threshold: " + self.get_fail_threshold())


    def load(self, filename):
        """
        Loads the actual file into a structure known to pyyaml.
        """

        self.output.set_title("Loading configuration from " + filename + "...")

        if path.exists(filename):

            with open(filename) as config_file:
                yaml_object = yaml.load(config_file, Loader=yaml.FullLoader)
                self.parse(yaml_object)

        else:
            self.output.add("[x] failed!")

        self.output.flush()


    def __init__(self, output_wrapper, filename="summit.yml"):

        self.output = output_wrapper

        # Define the various configuration fields
        self.fail_threshold = ""

        # Load the configuration file
        self.load(filename)

        pass