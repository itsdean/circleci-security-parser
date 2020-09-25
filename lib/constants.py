
def an(word):
    triggers = ["a", "e", "i", "o"]

    if word[0].lower() in triggers:
        return "an " + word
    else:
        return "a " + word


CVSS_LOW_MIN = 0.1
CVSS_LOW_MAX = 3.9
CVSS_MED_MIN = 4.0
CVSS_MED_MAX = 6.9
CVSS_HIGH_MIN = 7.0
CVSS_HIGH_MAX = 8.9
CVSS_CRIT_MIN = 9.0
CVSS_CRIT_MAX = 10.0


def convert_cvss(cvss):
    cvss = int(cvss)
    if CVSS_LOW_MIN <= cvss <= CVSS_LOW_MAX:
        return "low"
    elif CVSS_MED_MIN <= cvss <= CVSS_MED_MAX:
        return "medium"
    elif CVSS_HIGH_MIN <= cvss <= CVSS_HIGH_MAX:
        return "high"
    elif CVSS_CRIT_MIN <= cvss <= CVSS_CRIT_MAX:
        return "critical"
    else:
        return "unknown"