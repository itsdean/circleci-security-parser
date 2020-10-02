import logging
import sys
import yaml

from os import path
from ..output.Logger import Logger

class ConfigHandler:


    def __init__(self, logger, filename):

        self.l = logger

        # Define the various configuration fields
        # By default, parser builds fail if an issue with severity high or
        # above was found.
        self.fail_threshold = "high"
        self.allowlisted_issues = []
        self.upload_to_aws = False

        # Load the configuration file
        self.load(filename)


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
                self.l.info(f"fail_threshold set to {self.fail_threshold}")

        if "allowlist" in yaml_object:
            self.allowlisted_issues = yaml_object["allowlist"]
            if "ids" in self.allowlisted_issues:
                self.l.info(f"Loaded {len(self.allowlisted_issues['ids'])} allowed ID(s) from config file")
            if "paths" in self.allowlisted_issues:
                self.l.info(f"Loaded {len(self.allowlisted_issues['paths'])} allowed path(s) from config file")

        if "aws" in yaml_object:
            self.upload_to_aws = yaml_object["aws"]


    def load(self, filename):
        """
        Loads the actual file into a structure known to pyyaml.
        """

        self.l.info(f"Loading configuration from {filename}")

        if path.exists(filename):

            with open(filename) as config_file:
                # self.l.debug(f"{filename} found")

                yaml_object = yaml.load(config_file, Loader=yaml.FullLoader)
                if yaml_object is not None:
                    self.parse(yaml_object)
                else:
                    self.l.warning("yaml_object is None")

        else:
            self.l.warning(f"{filename} not found - skipping YAML parse stage")

        print()
