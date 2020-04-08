#!/usr/bin/env python3

import argparse
import boto3
import os
import traceback

from lib.input.ConfigHandler import ConfigHandler
from lib.input.Loader import Loader
from lib.issues.IssueHolder import IssueHolder
from lib.parsers.CoreParser import CoreParser
from lib.output.OutputWrapper import OutputWrapper
from lib.output.Reporter import Reporter

from dotenv import load_dotenv
load_dotenv()

if __name__ == "__main__":

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
		"--aws",
		help="Sets the uploading of the output to an S3 bucket",
		action="store_true"
	)
	parser.add_argument(
		"-v",
		"--verbose",
		help="Sets verbose mode",
		action="store_true"
	)

	# parser.add_argument(
	# 	"--fail",
	# 	help="Return an error code for",
	# 	choices=["critical", "high", "medium", "low", "informational"]
	# )

	arguments = parser.parse_args()

	# Create variables to store where to load and save files from/to.
	input_folder = arguments.input
	output_folder = arguments.output
	verbose = arguments.verbose
	aws = arguments.aws

	# Instantiate the various Object instances that we require
	output_wrapper = OutputWrapper(verbose)

	print()
	output_wrapper.add("CircleCI Security Output Parser (CSOP) - Hi there!")
	output_wrapper.add("To be used with https://https://circleci.com/orbs/registry/orb/salidas/security\n")
	output_wrapper.flush(show_time=False)

	config = ConfigHandler(output_wrapper)
	issue_holder = IssueHolder(output_wrapper)
	loader = Loader(output_wrapper)

	# Get the absolute path for the output folder
	output_folder = os.path.abspath(output_folder)

	reporter = Reporter(output_wrapper, issue_holder, output_folder)

	output_wrapper.set_title("Setting fail threshold")

	# Create a variable to store the severity, but only if it wasn't loaded
	# from the config file already AND a new value has been provided
	fail_threshold = config.get_fail_threshold()

	output_wrapper.add("fail threshold set to: " + fail_threshold)
	output_wrapper.flush(verbose=True)

	# Get a list of files containing parsable tool output
	files = loader.load_from_folder(input_folder)

	# load_from_folder will return 0 if no files were found
	if files != 0:

		# Create Reporter and Parser objects then pass their required parameters to them.
		parser = CoreParser(output_wrapper, issue_holder, files)

		# Check if any issues are whitelisted.
		parser.check_whitelists(config)

		# Check if we have a severity threshold and if any issues meet it.
		error_code = parser.check_threshold(fail_threshold)

		# If any issues met our threshold, fail the script.
		if error_code != 0:
			output_wrapper.set_title("[x] Exiting script with return code " + str(error_code) + "!")
			output_wrapper.flush()
			exit(error_code)

		reporter.create_csv_report()
		reporter.s3(aws, files)
		
	else:
		# We didn't find any files.
		output_wrapper.set_title("[x] No supported files were found! Did you target the right directory?")
		output_wrapper.flush()
