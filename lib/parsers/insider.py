import json

from lib.constants import get_rating

def parse(input_file, issue_holder, logger):
    """
    Goes through findings reported by insider-cli and passes issues to Reporter
    for output standardisation
    """

    issue_type = "code"
    tool_name = "insider"

    json_object = json.load(input_file)
    vulnerabilities = json_object["vulnerabilities"]

    for vuln in vulnerabilities:
        title = vuln["longMessage"].split(". ")[0]

        # Combine the issue descriptions from insider-cli first, then add the code after
        description = vuln["longMessage"].split(". ")[1] + "\n"
        description += "\nAn example of the offending code can be seen below:\n" + vuln["method"]

        # if "affectedFiles" in vuln.keys():
        #     location = ", ".join(vuln["affectedFiles"])
        # else:
        #     location = vuln["classMessage"]

        location = vuln["classMessage"].split(" (")[0]

        recommendation = vuln["shortMessage"]

        rating = vuln["cvss"]
        severity = get_rating(rating)
        # print(str_rating)

        issue_holder.add(
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            raw_output = vuln,
            severity = severity
        )

    logger.debug(f"> insider: {len(vulnerabilities)} issues reported\n")