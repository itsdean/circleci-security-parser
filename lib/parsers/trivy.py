import json

def parse(trivy_file, issue_holder, logger):
    """
    Goes through trivy tool output and passes issues to Reporter.
    """

    issue_type = "containers"
    tool_name = "trivy"

    filename = trivy_file.name

    # Load the issues into a JSON blob. The output is an element in a list, so we'll explode it out
    json_object = json.load(trivy_file)[0]

    # The location is the container being scanned
    location = json_object["Target"]

    findings = json_object["Vulnerabilities"]

    # Create a temporary list to store packages (as we need to merge their vulns into one object)
    temp_issue_storage = []

    for issue in findings:

        # We need to coalesce the packages into single issues - there's far too many if we do it individually
        if "PkgName" in issue:
            package = issue["PkgName"]

        if "InstalledVersion" in issue:
            version = issue["InstalledVersion"]

        severity = issue["Severity"].lower()

        # Steps:
        # 1) Check if package is already in temp_issue_storage
        # 2a) If it is, add the vulnerability information and/or CVE in the description
        # 2b) If it isn't, do 2a but after making a new dict. Add it to temp_issue_storage.

        if "Description" in issue:
            description = "- " + issue["VulnerabilityID"] + " (" + severity.capitalize() + ") - " + issue["Description"]

        # If the list is empty, or we've never seen this package before, create a new dict for it
        if len(temp_issue_storage) == 0 or not any(temp_issue["package"] == package for temp_issue in temp_issue_storage):

            description_start = f"Version {version} of {package} was present on the container, which is at risk from publicly known vulnerabilities.\n\nThe package was vulnerable to:"

            temp_issue = {
                "package": package,
                "title": f"Vulnerabilities identified for {package}",
                "description": description_start + "\n" + description + "\n",
                "recommendation": f"Upgrade {package} to the latest at least {issue["FixedVersion"]} to make use of the most recent security patches and fixes. Please note that this may break required features of the currently used version; it is recommended to test and assess the impact of the upgrade before carrying this out in a production environment.",
                "severity": severity
            }

            temp_issue_storage.append(temp_issue)

        # If we've seen the package before, then add this new finding's vulnerability to the existing package's list of vulnerabilities.
        for temp_issue in temp_issue_storage:
            if temp_issue["package"] == package and description not in temp_issue["description"]:
                temp_issue["description"] += description + "\n"

    # Now that we have all the issues sorted per package, add it to Reporter.
    for issue in temp_issue_storage:

        issue_holder.add(
            issue_type,
            tool_name,
            issue["title"],
            issue["description"],
            location,
            issue["recommendation"],
            filename,
            raw_output = issue,
            severity = issue["severity"]
        )

    logger.debug(f"> trivy: {len(temp_issue_storage)} issues reported\n")