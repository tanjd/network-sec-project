import os

from dotenv import load_dotenv


class RouterConfig:
    def __init__(self, name, env_file=".env") -> None:
        # Load environment variables from the specified file (default: .env)
        load_dotenv(env_file)

        # Define your environment variables here
        self.name: str = name
        # self.ip: str = os.getenv(f"{name}_ROUTER_IP")
        self.mac: str = os.getenv(f"{name}_MAC")

        self.host: str = os.getenv("HOST")
        self.port: int = int(os.getenv(f"{name}_PORT"))
