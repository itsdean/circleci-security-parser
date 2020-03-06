from datetime import datetime

class Outputter:

    def clear(self):
        self.title = ""
        self.buffer = list()


    def get(self):
        tmp = self.buffer
        tmp.insert(0, self.title)
        return tmp


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


    def print(self, string):
        print(self.time() + " " + string)


    def time(self):
        return "[" + datetime.now().strftime("%H:%M:%S") + "]"


    def flush(self, border=True, new=True):

        import constants

        max_length = self.get_max_length()

        if border:
            self.print(">" * max_length)

        if self.title != "":
            self.print(self.title)
            # Draw another divider if there's text to be printed after the title.
            if len(self.buffer) > 0:
                self.print("-" * max_length)

        for line in self.buffer:
           self.print(line)

        if border:
            self.print("<" * max_length)

        if new:
            print()

        self.buffer = list()

    def add(self, line):
        self.buffer.append(line)

    def __init__(self):
        self.clear()