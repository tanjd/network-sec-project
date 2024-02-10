import os

from dotenv import load_dotenv


class NodeConfig:
    def __init__(self, name: str, env_file=".env") -> None:
        # Load environment variables from the specified file (default: .env)
        load_dotenv(env_file)

        if name == "N1":
            router_name = "R1"
        else:
            router_name = "R2"

        # # Define your environment variables here
        # self.name: str = name
        # self.node_ip: str = os.getenv(f"{name}_NODE_IP")
        # self.node_mac: str = os.getenv(f"{name}_NODE_MAC")
        # self.router_mac: str = os.getenv(f"{router_name}_ROUTER_MAC")
        # self.host: str = os.getenv("HOST")
        # self.router_port: int = int(os.getenv(f"{router_name}_PORT"))
        # self.port: int = int(os.getenv(f"{name}_PORT"))
