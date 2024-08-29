import logging
import sys

format = "[{asctime},{msecs:03.0f}]:[{levelname}]:[{name}]:{message}"
dateformat = "%d.%m.%Y %H:%M:%S"
styleformat = "{"


def setup_log(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    stdouthandler = logging.StreamHandler(sys.stdout)
    stdouthandler.setLevel(logging.DEBUG)
    stdouthandler.addFilter(lambda record: record.levelno < logging.WARNING)
    stderrhandler = logging.StreamHandler(sys.stderr)
    stderrhandler.setLevel(logging.WARNING)
    stderrhandler.addFilter(lambda record: record.levelno >= logging.WARNING)
    stdouthandler.setFormatter(
        logging.Formatter(fmt=format, datefmt=dateformat,
                          style=styleformat))
    stderrhandler.setFormatter(
        logging.Formatter(fmt=format, datefmt=dateformat,
                          style=styleformat))
    logger.addHandler(stdouthandler)
    logger.addHandler(stderrhandler)
    return logger
