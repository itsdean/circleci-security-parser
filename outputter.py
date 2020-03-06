class Outputter:

    def get_max_length(self):

        # self.title has a length of 0 on init, so even
        # if self.title is not set to anything else,
        # we will still have a minimum value to start with. 
        length = len(self.title)

        for line in self.buffer:
            if len(line) > length:
                length = len(line)

        return length

    def set_title(self, title):
        self.title = title

    def flush(self, border=True, new=True):

        import constants

        max_length = self.get_max_length()

        if border:
            print(">" * max_length)

        if self.title != "":
            print(self.title)
            print("-" * max_length)

        for line in self.buffer:
            print(line)

        if border:
            print("<" * max_length)

        if new:
            print()

        self.buffer = []

    def add(self, line):
        self.buffer.append(line)

    def __init__(self):
        self.buffer = []
        self.title = ""