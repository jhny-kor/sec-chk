try:
    process()
except Exception as exc:
    logger.warning("request failed: %s", exc)
