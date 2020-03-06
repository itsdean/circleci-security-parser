from datetime import datetime
from textwrap import TextWrapper, fill

class Outputter:

    def clear(self):
        self.title = ""
        self.buffer = list()


    def get(self):
        tmp = self.buffer
        tmp.insert(0, self.title)
        return tmp


    def get_max_line_length(self):

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


    def print(self, line, max_width=-1):

        if max_width >= 0:
            tw = TextWrapper()
            tw.width = max_width
            tw.subsequent_indent = self.get_time() + " "
            line = tw.fill(line)

        print(self.get_time() + " " + line)


    def get_time(self):
        return "[" + datetime.now().strftime("%H:%M:%S") + "]"


    def flush(self, border=True, new=True):

        max_line_length = self.get_max_line_length()

        if max_line_length > self.max_terminal_width:
            max_line_length = self.max_terminal_width

        if border:
            self.print(">" * max_line_length)

        if self.title != "":
            self.print(self.title)
            # Draw another divider if there's text to be printed after the title.
            if len(self.buffer) > 0:
                self.print("-" * max_line_length)

        for line in self.buffer:
           self.print(line, max_width=max_line_length)

        if border:
            self.print("<" * max_line_length)

        if new:
            print()

        self.buffer = list()

    def add(self, line):
        self.buffer.append(line)

    def __init__(self):
        import subprocess
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        self.max_terminal_width = int(columns) - 15

        self.clear()