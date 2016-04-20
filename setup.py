from distutils.core import setup

setup(name="candump-parser",
      version="0.2",
      packages=["vehicle_log_parser", "vehicle_log_parser/utils"],
      scripts=["scripts/print-iso-sessions"])
