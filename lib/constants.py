
def an(word):
    triggers = ["a", "e", "i", "o"]

    if word[0].lower() in triggers:
        return "an " + word
    else:
        return "a " + word