import json

from ..constants import an

def parse(gitleaks_file, issue_holder, logger):
    """
    Goes through gitleaks --verbose output, combines them into a proper JSON
    object, then passes each reported issue to Reporter.
    """

    issue_type = "secrets"
    tool_name = "gitleaks"

    # Due to the potential risk of it being a real credential, we should always make these stand out.
    severity = "medium"

    # We'll use the same recommendation as burrow for now because of the
    # relative uncertainty in some findings. We can tweak this as we make
    # the gitleaks file more picky and specific.
    recommendation = "Please identify whether this finding is valid."

    gitleaks_issues = json.load(gitleaks_file)

    for issue in gitleaks_issues:

        if "key" in issue["tags"]:
            title = f"Potential {issue['rule']} match"
            # description = "A string matching a key was found in a file/. Gitleaks reported it as \"{}\".".format(an(issue["rule"]))
            description = f"A string matching a key was found in a file; gitleaks reported it as \"{an(issue['rule'].lower())}\".\n\nThe offence can be found below:\n{issue['offender']}"
        else:
            title = issue["rule"]
            description = f"A potential credential was found in a file. Gitleaks reported it as \"{an(issue['rule'].lower())}\".\n\nThe offence can be found below:\n{issue['offender']}"

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
            severity = severity,
            raw_output = issue
        )

    logger.debug(f"> gitleaks: {len(gitleaks_issues)} issues reported\n")