#!/usr/bin/env python3
# filepath: Shost/tools/manage_agents.py

import json
import hashlib
import secrets
import os
import sys
import datetime
from tabulate import tabulate
from colorama import Fore, Style, init
import argparse

# Initialize colorama for cross-platform colored output
init()

# Define paths - FIX: Use absolute path based on script location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SHOST_DIR = os.path.dirname(SCRIPT_DIR)
AGENTS_FILE = os.path.join(SHOST_DIR, "data", "agents.json")

def load_agents():
    """Load the agents from JSON file."""
    try:
        with open(AGENTS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{Fore.YELLOW}Warning: agents.json not found at {AGENTS_FILE}{Style.RESET_ALL}")
        print(f"Creating new file.")
        os.makedirs(os.path.dirname(AGENTS_FILE), exist_ok=True)
        return {}
    except json.JSONDecodeError:
        print(f"{Fore.RED}Error: agents.json is corrupted.{Style.RESET_ALL}")
        sys.exit(1)

def save_agents(agents):
    """Save agents to JSON file."""
    with open(AGENTS_FILE, 'w') as f:
        json.dump(agents, f, indent=2)
    print(f"{Fore.GREEN}Agents saved to {AGENTS_FILE}{Style.RESET_ALL}")

def display_agents(agents):
    """Display all agents in a table format."""
    if not agents:
        print(f"{Fore.YELLOW}No agents found.{Style.RESET_ALL}")
        return
    
    table_data = []
    for agent_id, agent_info in agents.items():
        # Check if agent is registered (full agent) or pre-registered
        if "status" in agent_info:
            # This is a fully registered agent
            status = f"{Fore.GREEN}REGISTERED{Style.RESET_ALL}"
            token_status = f"{Fore.GREEN}ACTIVE{Style.RESET_ALL}"
            vm_name = agent_info.get("vm_name", "Unknown")
            created = agent_info.get("registered_at", "Unknown")
            last_seen = agent_info.get("last_updated", "Unknown")
        else:
            # This is a pre-registered agent with enrollment key
            status = f"{Fore.BLUE}NOT REGISTERED{Style.RESET_ALL}"
            if agent_info.get("enrollment_key_hash"):
                token_status = f"{Fore.BLUE}GENERATED{Style.RESET_ALL}"
            else:
                token_status = f"{Fore.YELLOW}NO TOKEN{Style.RESET_ALL}"
                
            vm_name = agent_info.get("vm_name", "Unknown")
            created = agent_info.get("created_at", "Unknown")
            last_seen = "Never"
            
        name = agent_info.get("name", "Unnamed")
        
        table_data.append([agent_id, name, vm_name, status, token_status, created, last_seen])
    
    headers = ["Agent ID", "Name", "VM Name", "Status", "Token", "Created", "Last Seen"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def generate_token(agent_id, agents):
    """Generate a new enrollment token for an agent."""
    # Generate random enrollment key
    enrollment_key = secrets.token_urlsafe(32)
    
    # Hash the key for storage
    key_hash = hashlib.sha256(enrollment_key.encode()).hexdigest()
    
    # Get or create agent info
    if agent_id in agents:
        agent_info = agents[agent_id]
        # If agent is already registered, prevent token generation
        if "status" in agent_info and agent_info["status"] == "registered":
            print(f"{Fore.RED}Error: Agent {agent_id} is already registered. Cannot generate new token.{Style.RESET_ALL}")
            return None
    else:
        name = input(f"Enter name for new agent {agent_id}: ")
        agent_info = {"name": name if name else f"Agent {agent_id}"}
    
    # Update agent info for enrollment
    agent_info["enrollment_key_hash"] = key_hash
    agent_info["enrollment_used"] = False
    agent_info["created_at"] = datetime.datetime.now().isoformat()
    
    # Save to agents collection
    agents[agent_id] = agent_info
    save_agents(agents)
    
    print(f"\n{Fore.GREEN}✅ Enrollment token generated for {agent_id}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
    print(f"{Fore.WHITE}ENROLLMENT KEY: {Fore.GREEN}{enrollment_key}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
    print(f"\nUse this key to register: {Fore.CYAN}ShikraAgent.exe --register {enrollment_key}{Style.RESET_ALL}")
    
    return enrollment_key

def create_new_agent(agents):
    """Create a new agent for pre-registration."""
    agent_id = input(f"{Fore.CYAN}Enter agent ID (e.g., agent-win11): {Style.RESET_ALL}").strip()
    
    if not agent_id:
        print(f"{Fore.RED}Agent ID cannot be empty.{Style.RESET_ALL}")
        return
    
    # Check if agent already exists
    if agent_id in agents:
        print(f"{Fore.YELLOW}Agent {agent_id} already exists.{Style.RESET_ALL}")
        
        # Check if already registered
        if "status" in agents[agent_id] and agents[agent_id]["status"] == "registered":
            print(f"{Fore.RED}This agent is already registered and active.{Style.RESET_ALL}")
            return
            
        # Ask to generate token if not registered
        choice = input(f"{Fore.YELLOW}Generate enrollment token for {agent_id}? (y/n): {Style.RESET_ALL}").lower()
        if choice == 'y':
            generate_token(agent_id, agents)
        return
    
    # Get agent name
    name = input(f"{Fore.CYAN}Enter agent name (e.g., Windows 11 Analysis VM): {Style.RESET_ALL}").strip()
    if not name:
        name = f"Agent {agent_id}"
    
    # Create agent with name and generate token
    agents[agent_id] = {"name": name}
    generate_token(agent_id, agents)

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Manage Shikra agents and enrollment tokens.')
    parser.add_argument('--list', action='store_true', help='List all agents')
    parser.add_argument('--create', metavar='AGENT_ID', help='Create new agent with specified ID')
    parser.add_argument('--generate', metavar='AGENT_ID', help='Generate enrollment token for agent')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    
    args = parser.parse_args()
    
    # Load agents
    agents = load_agents()
    
    # List agents
    if args.list or not (args.create or args.generate or args.interactive):
        print(f"\n{Fore.BLUE}=== Shikra Agent List ==={Style.RESET_ALL}\n")
        display_agents(agents)
        return
    
    # Generate token for existing agent
    if args.generate:
        generate_token(args.generate, agents)
        return
    
    # Create new agent
    if args.create:
        agents[args.create] = {
            "name": f"Agent {args.create}",
            "created_at": datetime.datetime.now().isoformat()
        }
        print(f"{Fore.GREEN}Agent {args.create} created. Generating enrollment token...{Style.RESET_ALL}")
        generate_token(args.create, agents)
        return
    
    # Interactive mode
    if args.interactive:
        print(f"\n{Fore.BLUE}=== Shikra Agent Management ==={Style.RESET_ALL}")
        
        while True:
            print(f"\n{Fore.CYAN}1. List agents{Style.RESET_ALL}")
            print(f"{Fore.CYAN}2. Create new agent{Style.RESET_ALL}")
            print(f"{Fore.CYAN}3. Generate enrollment token{Style.RESET_ALL}")
            print(f"{Fore.CYAN}4. Exit{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.WHITE}Enter choice (1-4): {Style.RESET_ALL}").strip()
            
            if choice == "1":
                display_agents(agents)
            elif choice == "2":
                create_new_agent(agents)
            elif choice == "3":
                agent_id = input(f"{Fore.CYAN}Enter agent ID: {Style.RESET_ALL}").strip()
                if agent_id:
                    generate_token(agent_id, agents)
                else:
                    print(f"{Fore.RED}Agent ID cannot be empty.{Style.RESET_ALL}")
            elif choice == "4":
                print(f"{Fore.GREEN}Exiting...{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid choice.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()