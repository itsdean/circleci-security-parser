import json

from lib.constants import get_rating

def parse(input_file, issue_holder, output_wrapper):
    """
    Goes through findings reported by insider-cli and passes issues to Reporter
    for output standardisation
    """

    issue_type = "code"
    tool_name = "insider"

    json_object = json.load(input_file)
    vulnerabilities = json_object["vulnerabilities"]

    output_wrapper.add("- There are " + str(len(vulnerabilities)) + " issues to report!")

    for vuln in vulnerabilities:
        title = vuln["longMessage"].split(". ")[0] + "."

        # Combine the issue descriptions from insider-cli first, then add the code after
        description = vuln["longMessage"] + "\n"
        description += "\nAn example of the offending code can be seen below:\n" + vuln["method"]

        if "affectedFiles" in vuln.keys():
            location = "\n".join(vuln["affectedFiles"])
        else:
            location = vuln["class"]

        recommendation = vuln["shortMessage"]

        # todo: logic to calculate severity
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

    output_wrapper.add("[✓] Done!")