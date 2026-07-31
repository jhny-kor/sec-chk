try:
    process()
except ValueError:
    logger.warning("request failed")
