"""
InfraRed macOS Agent Entry Point
사용법: sudo python3 main.py --server-url https://api.infrared.io --token <TOKEN>
"""
import argparse, logging
from collectors.unified_log_collector import MacOSUnifiedLogCollector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def main():
    parser = argparse.ArgumentParser(description="InfraRed macOS Security Agent")
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--agent-id", default="macos-agent-001")
    parser.add_argument("--tenant-id", default="")
    args = parser.parse_args()

    collector = MacOSUnifiedLogCollector(
        server_url=args.server_url,
        agent_jwt=args.token,
        agent_id=args.agent_id,
        tenant_id=args.tenant_id,
    )
    collector.start()

if __name__ == "__main__":
    main()
