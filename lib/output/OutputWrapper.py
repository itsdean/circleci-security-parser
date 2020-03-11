from datetime import datetime
from textwrap import TextWrapper, fill

class OutputWrapper:
    """
    Custom library used to print parser output. Currently adds timing and pretty borders to each blob of output.
    """

    def set_time(self, show_time):
        """
        Used to set the variable self.show_time, that determines if a printed line should be prepended with the current timestamp.
        """

        self.show_time = show_time


    def clear(self):
        """
        Empty the current buffer.
        """

        self.title = ""
        self.buffer = list()


    def get(self):
        """
        Return the entire buffer, with the title (if existent) inserted at the top/front of the list.
        """

        tmp = self.buffer
        tmp.insert(0, self.title)
        return tmp


    def get_longest_line_length(self):
        """
        Find the line in the buffer with the longest length and return its value.
        """

        # self.title has a length of 0 on init, so even
        # if self.title is not set to anything else,
        # we will still have a minimum value to start with
        # that doesn't have to be 0.
        length = len(self.title)

        for line in self.buffer:
            if len(line) > length:
                length = len(line)

        return length


    def set_title(self, title):
        """
        Set the title of a buffer.
        """

        self.title = title


    def print(self, line, max_width=-1, show_time=True):
        """
        Print out a line.

        It is possible to specify the max width of the line, at which point the remainder of the text will wrap. Good if you have ceiling and floor banenrs for a blob of text.
        """

        if max_width >= 0:
            tw = TextWrapper()
            tw.width = max_width
            if show_time:
                tw.subsequent_indent = self.get_time() + " "
            line = tw.fill(line)

        if show_time:
            print(self.get_time() + " " + line)
        else:
            print(line)


    def get_time(self):
        """
        Return the current time in hours, minutes and seconds, surrounded by square brackets.
        """

        return "[" + datetime.now().strftime("%H:%M:%S") + "]"


    def flush(self,
            border=True,
            new=True,
            show_time=True,
            verbose=False
        ):
        """
        Empties the buffer, printing out all stored strings.

        The flushed output can have a border too to isolate from other output
        (for clarity for example).

        By default a new line is printed after the buffer is flushed.
        """

        # What's the longest line in the buffer?
        buffer_longest_line_length = self.get_longest_line_length()

        # If max_line_length 
        if buffer_longest_line_length > self.max_terminal_width:
            buffer_longest_line_length = self.max_terminal_width

        if border:
            self.print(">" * buffer_longest_line_length, show_time=show_time)

        # If there's a title, print it.
        if self.title != "":
            self.print(self.title, show_time=show_time)
            # Draw another divider if there's text to be printed after the title.
            if len(self.buffer) > 0:
                self.print("-" * buffer_longest_line_length, show_time=show_time)

        for line in self.buffer:
           self.print(line, max_width=buffer_longest_line_length, show_time=show_time)

        if border:
            self.print("<" * buffer_longest_line_length, show_time=show_time)

        if new:
            print()

        # Flush the title and buffer
        self.clear()


    def add(self, line):
        """
        Adds a line to be printed to the buffer.
        """
        self.buffer.append(line)


    def __init__(self):
        """
        Standard init procedure.
        """

        # This variable determines if, when printing, that the current time 
        # should be added to the beginning of the line.
        # Currently, this only affects the printing of the splash banner when 
        # running the script.
        self.show_time = True
  
        # To prevent truncation or bad wrapping, we leverage the textwrap 
        # package. In order to know where to wrap, we use the width of the 
        # terminal as a baseline and reduce from there.
        # Call stty size to get the width and height of the terminal.
        import subprocess
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        # We remove 10 from max_terminal_width to be on the safe side.
        self.max_terminal_width = int(columns) - 10

        self.clear()
