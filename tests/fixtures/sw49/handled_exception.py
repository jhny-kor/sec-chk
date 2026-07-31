try:
    process()
except ValueError as exc:
    logger.warning("invalid input: %s", exc)
