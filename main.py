#!/usr/bin/env python3

import argparse
import boto3
import os
import traceback

from lib.input.ConfigHandler import ConfigHandler
from lib.input.Loader import load_from_folder
from lib.issues.IssueHolder import IssueHolder
from lib.parsers.CoreParser import CoreParser
from lib.output.Logger import Logger
from lib.output.Reporter import Reporter

from dotenv import load_dotenv
load_dotenv()

if __name__ == "__main__":

	print()
	print("Security Output Parser")
	print("To be used with https://https://circleci.com/orbs/registry/orb/salidas/security\n")

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
		"-v",
		"--verbose",
		help="Sets verbose mode",
		action="store_true"
	)
	parser.add_argument(
		"-c",
		"--config",
		help="Location of config file to consume",
		default=""
	)

	arguments = parser.parse_args()

	# Create variables to store where to load and save files from/to.
	input_folder = arguments.input
	# If not provided, store output in the current directory (i.e. ".")
	output_folder = arguments.output 
	verbose = arguments.verbose

	# Prepare the logger that will be used throughout
	l = Logger(verbose)

	# Load the config file
	if arguments.config is "" or arguments.config is None:
		config = ConfigHandler(l, input_folder + ".security/parser.yml")
	else:
		config = ConfigHandler(l, arguments.config)

	issue_holder = IssueHolder(l)

	input_files = load_from_folder(l, input_folder)

	parser = CoreParser(l, issue_holder)
	parser.parse(input_files)
	parser.check_allowlists(config.allowlisted_issues)
	exit_code = parser.check_threshold(config.fail_threshold)

	# Get the absolute path for the output folder
	output_path = os.path.abspath(output_folder)

	# Create the reporter and generate output now
	reporter = Reporter(l, issue_holder, output_path)
	creation_success = reporter.create_csv_report()

	# If we have a report and we're allowed to upload to AWS, then do it
	if creation_success and config.upload_to_aws:
		reporter.upload_to_s3(input_files)

	if exit_code != 0:
		l.warning("Exiting script with non-zero value")
		l.warning(f"The exit code is {exit_code}")
		exit(exit_code)
