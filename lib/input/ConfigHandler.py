import yaml

from os import path

class ConfigHandler:


    def __init__(self, output_wrapper, filename):

        self.output = output_wrapper

        # Define the various configuration fields
        # By default, parser builds fail if an issue with severity high or
        # above was found.
        self.fail_threshold = "high"
        self.whitelisted_issues = []
        # self.aws = True
        self.aws = True

        # Load the configuration file
        self.load(filename)

        pass


    def set_whitelisted_issue_ids(self, issues):
        self.whitelisted_issues = issues


    def get_whitelisted_issue_ids(self):
        return self.whitelisted_issues


    def set_fail_threshold(self, fail_threshold):
        self.fail_threshold = fail_threshold


    def get_fail_threshold(self):
        return self.fail_threshold


    def is_aws_enabled(self):
        return self.aws


    def parse(self, yaml_object):
        """
        Obtains the various fields from the yaml file. 
        """

        if "fail_threshold" in yaml_object:
            self.set_fail_threshold(yaml_object["fail_threshold"])
            self.output.add("- fail_threshold: " + self.get_fail_threshold())

        if "whitelist" in yaml_object:
            self.set_whitelisted_issue_ids(yaml_object["whitelist"])
            self.output.add("- whitelist: loaded " + str(len(self.get_whitelisted_issue_ids())) + " ids")

        if "aws" in yaml_object:
            self.aws = yaml_object["aws"]


    def load(self, filename):
        """
        Loads the actual file into a structure known to pyyaml.
        """

        self.output.set_title("Loading configuration from " + filename + "...")

        if path.exists(filename):

            with open(filename) as config_file:
                self.output.add(".security/parser.yml file found!")
                yaml_object = yaml.load(config_file, Loader=yaml.FullLoader)

                self.parse(yaml_object)

        else:
            self.output.add("[x] No .security/parser.yml file found - loading failed!")

        self.output.flush()

