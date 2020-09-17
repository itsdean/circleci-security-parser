import json

def parse(shed_file, issue_holder, logger):
    """
    Goes through SHeD output, reporting concerning output as issues
    and passing them to Reporter.
    """

    issue_count = 0

    issue_type = "headers"
    tool_name = "SHeD"

    shed_object = json.load(shed_file)
    url = shed_object["request"]["url"]

    hsts = shed_object["hsts"]
    if not hsts["present"]:
        severity = "low"
        title = "No Strict-Transport-Security Header Present"
        description = """The HTTP Strict-Transport-Security (HSTS) header was not
returned by the requested URL.

The HSTS header instructs a browser to access the site/URL in
future requests over HTTPS only, rather than over HTTP."""
        recommendation = """Return a Strict-Transport-Security header with a secure value set;
see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security for information on configuration."""

        location = url
        filename = shed_file.name

        issue_holder.add(
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            filename,
            raw_output = hsts
        )

        issue_count += 1

    xframe = shed_object["xframe"]
    if not xframe["present"]:
        severity = "low"
        title = "No X-Frame-Options Header Present"
        description = """The X-Frame-Options header was not returned by the requested URL.

The X-Frame-Options header identifies whether a browser should
be allowed to frame a response, and can help to mitigate clickjacking
attacks."""
        # description = "The X-Frame-Options header was not returned by the requested URL."
        recommendation = """Return the X-Frame-Options header;
see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options for information on configuration."""
        
        location = url
        filename = shed_file.name

        issue_holder.add(
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            filename,
            raw_output = xframe
        )

        issue_count += 1

    xss = shed_object["xss"]
    if not xss["present"]:
        severity = "low"
        title = "No X-XSS-Protection Header Present"
        description = """The X-XSS-Protection header was not returned by the requested URL.

The X-XSS-Protection header instructs browsers on detection of an
attempted Cross-Site Scripting attack to either sanitise or remove
the attack, depending on the value of the header."""
        recommendation = """Return the X-XSS-Protection header with a secure value set;
see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection for information on configuration.

Please make your own judgment call separate from this finding - the
X-XSS-Protection header is no longer actively supported by modern browsers.
See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
for more information."""
        
        location = url
        filename = shed_file.name

        issue_holder.add(
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            filename,
            raw_output = xss
        )

        issue_count += 1
    
    # cookies = shed_object["cookies"]
    # if len(cookies) > 0:
    #     for cookie in cookies:
    #         print(cookie)
    #         if not cookie["httponly"]:
    #             print("no httponly")

    #         if not cookie["secure"]:
    #             print("no secure")
    

    curious = shed_object["curious"]
    if len(curious) > 0:
        for header in curious:
            header_dict_items = header.items()
            for header_tuple in header_dict_items:
                title = "Curious Header"
                description = """A potentially suspicious header was returned by the
requested URL.

The header was:
{}: {}""".format(header_tuple[0], header_tuple[1])
                recommendation = "Confirm whether the header is required to be returned. If not, consider omitting the header from future responses."

                issue_holder.add(
                    issue_type,
                    tool_name,
                    title,
                    description,
                    location,
                    recommendation,
                    filename,
                    raw_output = header
                )

                issue_count += 1

    logger.debug(f"> shed: {issue_count} issues reported\n")