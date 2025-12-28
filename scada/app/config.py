from dotenv import load_dotenv
import logging
import os

load_dotenv()

# App Configuration
# AUTHORIZATION_TOKEN = os.environ['AUTHORIZATION_TOKEN']
CONCURRENCY_LIMIT = 50


# Host and Port Settings
PORT = "8000"
HOST = "0.0.0.0"

# Logging Configuration
logger = logging.getLogger('SEC537')
formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s',
                              "%Y-%m-%d %H:%M:%S")

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

logger.addHandler(stream_handler)
logger.setLevel(logging.INFO)

app_logger = logger
