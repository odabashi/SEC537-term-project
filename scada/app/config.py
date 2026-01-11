from dotenv import load_dotenv
import logging


load_dotenv()

# App Configuration
# AUTHORIZATION_TOKEN = os.environ['AUTHORIZATION_TOKEN']
CONCURRENCY_LIMIT = 50
APP_NAME = "SEC537_SCADA_System"

# Host and Port Settings
PORT = "8000"
HOST = "0.0.0.0"


# Logging Configuration
logger = logging.getLogger("SEC537_SCADA")
formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s',
                              "%Y-%m-%d %H:%M:%S")

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.INFO)
logger.addHandler(stream_handler)

file_handler = logging.FileHandler("scada.log")
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

logger.setLevel(logging.INFO)
logger.propagate = False
