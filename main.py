#!/usr/bin/env python3

import argparse
import os
import traceback

from lib.output.OutputWrapper import OutputWrapper
from parser import Parser
from pathlib import Path
from reporter import Reporter

if __name__ == "__main__":

	print()

	output_wrapper = OutputWrapper()

	output_wrapper.add("CircleCI Security Output Parser (CSOP) - Hi there!")
	output_wrapper.add("To be used with https://https://circleci.com/orbs/registry/orb/salidas/security\n")
	output_wrapper.flush(show_time=False)

	parser = argparse.ArgumentParser()
	parser.add_argument(
		"-i",
		"--input",
		help="The directory to load security tool output from",
		required=True
	)
	parser.add_argument(
		"-o",
		"--output",
		help="The directory to store the parsed data to",
		default="."
	)
	parser.add_argument(
		"--fail",
		help="Return an error code for",
		choices=["critical", "high", "medium", "low", "informational"]
	)

	arguments = parser.parse_args()

	# Create variables to store where to load and save files from/to.
	input_folder = arguments.input
	output_folder = arguments.output

	# Create a variable to store the, but only if it exists.
	if arguments.fail:
		fail_threshold = arguments.fail
	else:
		fail_threshold = "off"

	# o.set_title("fail threshold: " + fail_threshold + "\n")
	output_wrapper.set_title("fail threshold: " + fail_threshold)
	output_wrapper.flush()

	# Create a blank list to keep track of any security tool output
	files = []

	# Get the absolute path for the input folder
	input_folder = os.path.abspath(input_folder)

	output_wrapper.set_title("Loading from: " + input_folder)

	# Get the absolute path for the output folder
	output_folder = os.path.abspath(output_folder)

	# Create open file objects for all JSON files in the input folder
	# and store them in the files list object
	for fname in Path(input_folder).glob("**/results_*"):
		i_file = open(str(fname), "r")
		files.append(i_file)

	# Check if we were able to load any files
	if len(files) > 0:

		# Found some files! Lets list them.
		if len(files) == 1:
			output_wrapper.add("1 supported file was found!")
		else:
			output_wrapper.add(str(len(files)) + " supported files were found!")
		for f_object in files:
			output_wrapper.add("- " + os.path.basename(f_object.name))

		output_wrapper.flush()

		# Create Reporter and Parser objects then pass the list of file
		# objects (and the parser) to the parser.
		reporter = Reporter(output_folder)
		parser = Parser()
		parser.consume(files, reporter)

		# Check if we have a severity threshold. If we do, error_code will be > 0 so return that value to force the build to fail.
		error_code = parser.check_threshold(fail_threshold)

		# print(error_code)

		if error_code != 0:
			output_wrapper.set_title("[x] Exiting script with return code " + str(error_code) + "!")
			output_wrapper.flush()
			exit(error_code)

		reporter.create_report()
		
	else:
		# We didn't find any files; odd.
		output_wrapper.set_title("[x] No supported files were found! Did you target the right directory?")
		output_wrapper.flush()
