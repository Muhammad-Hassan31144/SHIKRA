#!/usr/bin/env python3
"""
Register an agent with the Shost API using actual agent credentials
This matches the format that the Windows agent configuration script uses
"""

import argparse
import requests
import json
import sys

def main():
    parser = argparse.ArgumentParser(description="Register an agent with Shost API")
    parser.add_argument("--host", default="http://192.168.100.1:8080", help="Shost API host URL")
    parser.add_argument("--agent-id", required=True, help="Agent ID (e.g., agent-COMPUTERNAME-12345)")
    parser.add_argument("--agent-secret", required=True, help="Agent secret (e.g., secret-12345-67890)")
    parser.add_argument("--name", help="Agent display name")
    parser.add_argument("--host-url", help="Host URL from agent perspective")
    parser.add_argument("--poll-interval", type=int, default=30000, help="Poll interval in milliseconds")
    parser.add_argument("--working-dir", default="C:\\Temp\\SecurityHealth", help="Agent working directory")
    parser.add_argument("--log-level", type=int, default=2, help="Log level (0=Debug, 1=Info, 2=Warning, 3=Error)")
    
    args = parser.parse_args()
    
    # Prepare registration payload
    payload = {
        "agent_id": args.agent_id,
        "agent_secret": args.agent_secret,
        "name": args.name or f"Agent {args.agent_id}",
        "capabilities": "file,registry,process,network,memory",
        "host_url": args.host_url or f"{args.host}/api/v1/",
        "poll_interval": args.poll_interval,
        "working_directory": args.working_dir,
        "log_level": args.log_level,
        "max_retries": 3,
        "execution_timeout": 300000,
        "enable_hooking": True,
        "enable_memory_dumps": True,
        "enable_network_capture": True
    }
    
    print(f"Registering agent {args.agent_id} with {args.host}...")
    print(f"Agent configuration:")
    print(f"  ID: {args.agent_id}")
    print(f"  Secret: {args.agent_secret[:8]}...")
    print(f"  Poll interval: {args.poll_interval}ms")
    print(f"  Working dir: {args.working_dir}")
    print()
    
    try:
        response = requests.post(
            f"{args.host}/api/v1/agent/register",
            json=payload,
            timeout=10
        )
        
        if response.ok:
            result = response.json()
            print("✅ Registration successful!")
            print(json.dumps(result, indent=2))
            return 0
        else:
            print(f"❌ Registration failed: {response.status_code}")
            try:
                error = response.json()
                print(json.dumps(error, indent=2))
            except:
                print(response.text)
            return 1
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Connection error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
