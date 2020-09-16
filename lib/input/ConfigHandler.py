import logging
import sys
import yaml

from os import path
from ..output.Logger import Logger

class ConfigHandler:


    def __init__(self, output_wrapper, filename):
        
        self.l = Logger("ConfigHandler")

        self.output = output_wrapper

        # Define the various configuration fields
        # By default, parser builds fail if an issue with severity high or
        # above was found.
        self.fail_threshold = "high"
        self.whitelisted_issues = []
        self.aws = False

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
            self.fail_threshold = yaml_object["fail_threshold"]

            if type(self.fail_threshold) is bool:
                self.l.error("fail_threshold is a bool, did you use double quotes when defining fail_threshold in the .yml file?")
                sys.exit(-1)
            else:
                self.l.debug(f"fail_threshold set to {self.fail_threshold}")

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
                self.output.add(f"{filename} found!")

                yaml_object = yaml.load(config_file, Loader=yaml.FullLoader)

                if yaml_object is not None:
                    self.parse(yaml_object)

        else:
            self.output.add(f"[x] {filename} not found - skipping parse stage!")

        self.output.flush()

