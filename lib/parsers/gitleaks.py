import json

from ..constants import an

def parse(gitleaks_file, issue_holder, logger):
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

    gitleaks_issues = json.load(gitleaks_file)

    for issue in gitleaks_issues:

        if "key" in issue["tags"]:
            title = "Potential {} match".format(issue["rule"])
            description = "A string matching a key was found in a file. Gitleaks reported it as {}.".format(an(issue["rule"]))

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

    logger.debug(f"> gitleaks: {len(gitleaks_issues)} issues reported\n")