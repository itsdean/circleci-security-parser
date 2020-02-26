
# -*- coding: utf-8 -*-

import json
import os
import constants
import re
from pprint import pprint

class Parser:
	"""
	Redirects files to their respective parsers to be processed.
	"""

	parsed_tools = {
		"gosec": "gosec",
		"nancy": "nancy",
		"burrow": "burrow",
		"Snyk [Node]": "snyk_node",
	}


	def gosec(self, i_file):
		from lib import gosec
		gosec.parse(i_file, self.reporter)


	def nancy(self, i_file):
		from lib import nancy
		nancy.parse(i_file, self.reporter)


	def burrow(self, i_file):
		from lib import burrow
		burrow.parse(i_file, self.reporter)


	def snyk_node(self, i_file):
		from lib import snyk
		snyk.parse_node(i_file, self.reporter)


	def get_file_source(self, i_file):
		"""
		Iterates through a dictionary of tools that can be parsed and compares their associated filename patterns with the file currently being processed.
		"""

		# Get the tool name ("Snyk [Node]" for example) and its associated matching filename ("snyk_node"), both from parsed_tools in KV format
		for toolname, filename_pattern in self.parsed_tools.items():
			# Alright, we've found a file from a tool that we support
			if filename_pattern in i_file.name:
				# Lets obtain a link to the correct tool parser we'll be using. Thanks getattr, you're the best!
				print("- Tool identified: " + toolname)
				# We could squash the below into one line but it's more confusing to understand if you don't know getattr.
				file_parser_method = getattr(self, filename_pattern)
				file_parser_method(i_file)


	def consume(self, files, reporter):
		"""
		Absorbs a list of files (and a reporter object) and attempts to have each file parsed depending on the tool (and support)
		"""

		# Set the output folder variable in case we need to save parsed output
		self.reporter = reporter

		for i_file in files:
			print(">" * constants.SEPARATOR_LENGTH)
			print("Parsing: " + os.path.basename(i_file.name))
			print("-" * constants.SEPARATOR_LENGTH)

			self.get_file_source(i_file)

			print("<" * constants.SEPARATOR_LENGTH + "\n")


