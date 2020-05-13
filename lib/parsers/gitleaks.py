import json

from ..constants import an

# tmp
from pprint import pprint

def create_json_object(gitleaks_file, output_wrapper):
    """
    Parses the file created by gitleaks and crafts it into a JSON object
    we can play around and parse.

    By default, gitleaks reports a JSON object for each offense, but does
    not combine them into a single well-formed JSON blob.

    This aims to solve that, returning a Python JSON object as a result.
    """

    # Create an empty array. This will store the individual JSON objects
    json_object = []

    # gitleaks_file is passed to this point as a file object already, hence
    # the lack of open().
    for line in gitleaks_file:
        tmp_json_object = json.loads(line)
        json_object.append(tmp_json_object)

    return json_object

def parse(gitleaks_file, issue_holder, output_wrapper):
    """
    Goes through gitleaks --verbose output, combines them into a proper JSON
    object, then passes each reported issue to Reporter.
    """

    issue_type = "secrets"
    tool_name = "gitleaks"

    # We'll use the same recommendation as burrow for now because of the
    # relative uncertainty in some findings. We can tweak this as we make
    # the gitleaks file more picky and specific.
    recommendation = "Please identify whether this finding is true or false positive."

    output_wrapper.add("- Creating well-formed JSON object for parsing")
    formatted_file = create_json_object(gitleaks_file, output_wrapper)

    output_wrapper.add("- {} findings reported by gitleaks!".format(len(formatted_file)))

    for issue in formatted_file:

        if "key" in issue["tags"]:
            title = "Key match"
            description = "A potential key was found in a file. Gitleaks reports this as {}.".format(an(issue["rule"]))

        location = issue["file"]
        filename = issue["file"]

        issue_holder.add(
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            filename,
            raw_output = issue
        )