import logging

formatter = logging.Formatter("%(asctime)s - %(name)s -  %(levelname)s - %(message)s")


class Logger(logging.Logger):
    def __init__(self, name, log_file=None):
        super().__init__(name)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.addHandler(console_handler)
        if log_file:
            self.log_file = log_file
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(formatter)
            self.addHandler(file_handler)
