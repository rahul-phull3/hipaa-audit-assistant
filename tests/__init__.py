import logging

# Expected failures (rejected keys, unusable answers, ...) are logged by design; keep them out of the test output.
_logger = logging.getLogger("hipaa_audit")
_logger.addHandler(logging.NullHandler())
_logger.propagate = False

# The multipart parser warns about every malformed upload the API tests send on purpose.
logging.getLogger("python_multipart").setLevel(logging.ERROR)
