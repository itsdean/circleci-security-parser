import json

from packaging import version
from ..constants import calculate_rating


def parse(trivy_file, issue_holder, logger):
    """
    Goes through trivy tool output and passes issues to Reporter
    """

    issue_type = "containers"
    tool_name = "trivy"

    filename = trivy_file.name

    # Load the issues into a JSON blob. The output is an element in a list, so we'll explode it out.
    json_object = json.load(trivy_file)[0]

    title = f"Vulnerable dependencies present within usage of {json_object['Type']}"
    location = json_object["Target"]

    # Chances are, the vulnerable packages are coming from the base image, so lets bunch the dependencies into one issue.
    
    findings = json_object["Vulnerabilities"]
    highest_severity = "informational"

    # Get a list of all the dependency package names and sort/uniq them.
    dependency_names = []
    for finding in findings:
        if finding["PkgName"] not in dependency_names:
            dependency_names.append(finding["PkgName"])

    sorted_issues = []
    description_issue_list = []

    # Go through all the findings and sort them such that we get the highest fix and severity for each finding.
    # We will also look for the greatest severity of all the packages, as this will be mapped to the parent issue.
    # O(n^2)
    for dependency_name in dependency_names:

        dependency_information = {
           "name": dependency_name,
           "installed": "unknown",
           "fix": "0.0.0",
           "severity": "unknown",
           "line": ""
        }

        for finding in findings:
            if dependency_name == finding["PkgName"]:

                # This shouldn't change
                dependency_information["installed"] = finding["InstalledVersion"]

                if version.parse(dependency_information["fix"]) < version.parse(finding["FixedVersion"]):
                    dependency_information["fix"] = finding["FixedVersion"]

                if calculate_rating(dependency_information["severity"]) < calculate_rating(finding["Severity"].lower()):
                    dependency_information["severity"] = finding["Severity"].lower()
            
            # Regardless of whether the packages match, we need to capture the highest severity issue in general.
            if calculate_rating(finding["Severity"].lower()) > calculate_rating(highest_severity):
                highest_severity = finding["Severity"].lower()

        description_issue_list.append(f'- {dependency_name} (severity: {dependency_information["severity"]}, installed: {dependency_information["installed"]}, fix: {dependency_information["fix"]})')
        sorted_issues.append(dependency_information)

    description = "trivy identified one or more vulnerable dependencies in use by the scanned container."
    description += f"\nThe highest severity issue was of {highest_severity} risk, and this has been reflected in the overall issue's severity."
    description += "\n\nThe following dependencies were identified as outdated/vulnerable:\n"
    
    for line in description_issue_list:
        description += f"{line}\n"

    recommendation = "It is recommended to upgrade the base image used to the scanned image, to make use of the most recent security patches and fixes.\n"
    recommendation += "Please note that this may break required features of the currently used version, and as such it is always recommended to test and assess the impact of upgrading the image(s) before deploying to production.\n\n"
    recommendation += "It may also be the case that reported dependencies were manually introduced as part of the creation of the scanned image - these may have to be manually upgraded also."

    issue_holder.add(
        issue_type,
        tool_name,
        title,
        description,
        location,
        recommendation,
        filename,
        raw_output = json_object,
        severity = highest_severity
    )

## this is old trivy code, reporting an issue for each dependency.

# def parse(trivy_file, issue_holder, logger):
#     """
#     Goes through trivy tool output and passes issues to Reporter.
#     """

#     issue_type = "containers"
#     tool_name = "trivy"

#     filename = trivy_file.name

#     # Load the issues into a JSON blob. The output is an element in a list, so we'll explode it out
#     json_object = json.load(trivy_file)[0]

#     # The location is the container being scanned
#     location = json_object["Target"]

#     findings = json_object["Vulnerabilities"]

#     # Create a temporary list to store packages (as we need to merge their vulns into one object)
#     temp_issue_storage = []

#     for issue in findings:

#         # We need to coalesce the packages into single issues - there's far too many if we do it individually
#         if "PkgName" in issue:
#             package = issue["PkgName"]

#         if "InstalledVersion" in issue:
#             version = issue["InstalledVersion"]

#         severity = issue["Severity"].lower()

#         # Steps:
#         # 1) Check if package is already in temp_issue_storage
#         # 2a) If it is, add the vulnerability information and/or CVE in the description
#         # 2b) If it isn't, do 2a but after making a new dict. Add it to temp_issue_storage.

#         if "Description" in issue:
#             description = "- " + issue["VulnerabilityID"] + " (" + severity.capitalize() + ") - " + issue["Description"]

#         # If the list is empty, or we've never seen this package before, create a new dict for it
#         if len(temp_issue_storage) == 0 or not any(temp_issue["package"] == package for temp_issue in temp_issue_storage):

#             description_start = f"Version {version} of {package} was present on the container, which is at risk from publicly known vulnerabilities.\n\nThe package was vulnerable to:"

#             temp_issue = {
#                 "package": package,
#                 "title": f"Vulnerabilities identified for {package}",
#                 "description": description_start + "\n" + description + "\n",
#                 "recommendation": f"Upgrade {package} to the latest at least {issue["FixedVersion"]} to make use of the most recent security patches and fixes. Please note that this may break required features of the currently used version; it is recommended to test and assess the impact of the upgrade before carrying this out in a production environment.",
#                 "severity": severity
#             }

#             temp_issue_storage.append(temp_issue)

#         # If we've seen the package before, then add this new finding's vulnerability to the existing package's list of vulnerabilities.
#         for temp_issue in temp_issue_storage:
#             if temp_issue["package"] == package and description not in temp_issue["description"]:
#                 temp_issue["description"] += description + "\n"

#     # Now that we have all the issues sorted per package, add it to Reporter.
#     for issue in temp_issue_storage:

#         issue_holder.add(
#             issue_type,
#             tool_name,
#             issue["title"],
#             issue["description"],
#             location,
#             issue["recommendation"],
#             filename,
#             raw_output = issue,
#             severity = issue["severity"]
#         )

#     logger.debug(f"> trivy: {len(temp_issue_storage)} issues reported\n")