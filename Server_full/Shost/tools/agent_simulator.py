#!/usr/bin/env python3
"""
Simple Agent Simulator for Shikra Host
Tests the agent polling, download, and status reporting workflow
"""

import requests
import hashlib
import hmac
import time
import json
import os
from datetime import datetime

class ShikraAgentSimulator:
    def __init__(self, host_url, agent_id, agent_secret):
        self.host_url = host_url.rstrip('/')
        self.agent_id = agent_id
        self.agent_secret = agent_secret
        self.session = requests.Session()
    
    def generate_hmac_headers(self, request_data=b''):
        """Generate HMAC authentication headers"""
        timestamp = str(int(time.time()))
        nonce = str(int(time.time() * 1000))  # milliseconds
        
        # Create message to sign
        message = f"{self.agent_id}{timestamp}{nonce}".encode('utf-8') + request_data
        
        # Generate HMAC signature
        signature = hmac.new(
            self.agent_secret.encode('utf-8'),
            message,
            hashlib.sha256
        ).hexdigest()
        
        return {
            'X-Agent-ID': self.agent_id,
            'X-Timestamp': timestamp,
            'X-Nonce': nonce,
            'X-Signature': signature
        }
    
    def poll_for_sample(self):
        """Poll the host for a new sample to analyze"""
        url = f"{self.host_url}/agent/next-sample"
        headers = self.generate_hmac_headers()
        
        print(f"🔍 Polling for samples at {url}")
        
        try:
            response = self.session.get(url, headers=headers)
            
            if response.status_code == 204:
                print("📭 No samples available")
                return None
            elif response.status_code == 200:
                data = response.json()
                print(f"📦 Received sample assignment:")
                print(f"   Sample ID: {data['sample_id']}")
                print(f"   Filename: {data['filename']}")
                print(f"   File Hash: {data['file_hash']}")
                print(f"   File Size: {data['file_size']} bytes")
                print(f"   Analysis ID: {data['analysis_id']}")
                return data
            else:
                print(f"❌ Error polling: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Exception while polling: {e}")
            return None
    
    def download_sample(self, sample_id, filename):
        """Download the sample file"""
        url = f"{self.host_url}/agent/download/{sample_id}"
        headers = self.generate_hmac_headers()
        
        print(f"⬇️ Downloading sample {sample_id}")
        
        try:
            response = self.session.get(url, headers=headers)
            
            if response.status_code == 200:
                # Save to local file
                local_filename = f"downloaded_{filename}"
                with open(local_filename, 'wb') as f:
                    f.write(response.content)
                
                print(f"✅ Sample downloaded successfully as {local_filename}")
                return local_filename
            else:
                print(f"❌ Download failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Exception while downloading: {e}")
            return None
    
    def report_status(self, sample_id, status, progress=0, current_stage=""):
        """Report analysis status back to host"""
        url = f"{self.host_url}/agent/status"
        
        data = {
            'sample_id': sample_id,
            'status': status,
            'progress': progress,
            'current_stage': current_stage,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Convert to JSON bytes for consistent HMAC calculation
        data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        headers = self.generate_hmac_headers(data_bytes)
        headers['Content-Type'] = 'application/json'
        
        print(f"📤 Reporting status: {status} ({progress}%) - {current_stage}")
        
        try:
            # Send the exact same bytes we used for HMAC calculation
            response = self.session.post(url, headers=headers, data=data_bytes)
            
            if response.status_code == 200:
                print("✅ Status reported successfully")
                return True
            else:
                print(f"❌ Status report failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Exception while reporting status: {e}")
            return False
    
    def simulate_analysis(self, sample_id, filename, local_file):
        """Simulate malware analysis process"""
        print(f"🔬 Starting analysis simulation for {filename}")
        
        # Report analysis start
        self.report_status(sample_id, 'running', 0, 'Starting analysis')
        time.sleep(1)
        
        # Simulate different analysis stages
        stages = [
            (10, 'File type detection'),
            (25, 'Static analysis'),
            (40, 'Unpacking'),
            (60, 'Dynamic analysis setup'),
            (75, 'Behavioral analysis'),
            (90, 'API hooking'),
            (95, 'Memory dump analysis'),
            (100, 'Report generation')
        ]
        
        for progress, stage in stages:
            self.report_status(sample_id, 'running', progress, stage)
            time.sleep(2)  # Simulate work
        
        # Report completion
        self.report_status(sample_id, 'completed', 100, 'Analysis complete')
        
        print(f"✅ Analysis simulation completed for {filename}")
        
        # Clean up downloaded file
        try:
            os.remove(local_file)
            print(f"🗑️ Cleaned up temporary file {local_file}")
        except:
            pass
    
    def run_polling_loop(self, poll_interval=30):
        """Run the main agent polling loop"""
        print(f"🚀 Starting Shikra Agent Simulator")
        print(f"   Host: {self.host_url}")
        print(f"   Agent ID: {self.agent_id}")
        print(f"   Poll Interval: {poll_interval} seconds")
        print("="*60)
        
        try:
            while True:
                # Poll for samples
                sample_data = self.poll_for_sample()
                
                if sample_data:
                    sample_id = sample_data['sample_id']
                    filename = sample_data['filename']
                    
                    # Download sample
                    local_file = self.download_sample(sample_id, filename)
                    
                    if local_file:
                        # Simulate analysis
                        self.simulate_analysis(sample_id, filename, local_file)
                    else:
                        # Report download failure
                        self.report_status(sample_id, 'failed', 0, 'Download failed')
                
                print(f"⏳ Waiting {poll_interval} seconds before next poll...")
                time.sleep(poll_interval)
                
        except KeyboardInterrupt:
            print("\n🛑 Agent simulator stopped by user")
        except Exception as e:
            print(f"❌ Agent simulator error: {e}")

def main():
    # Read agent configuration
    if os.path.exists('Shikra.ini'):
        print("📄 Reading configuration from Shikra.ini")
        
        # Simple INI parser
        config = {}
        with open('Shikra.ini', 'r') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
        
        host_url = config.get('host_api_url', 'http://192.168.100.1:8080/api/v1/')
        agent_id = config.get('agent_id', '')
        agent_secret = config.get('agent_secret', '')
        poll_interval = int(config.get('poll_interval_ms', '30000')) // 1000
        
    else:
        # Use default/hardcoded values for testing
        print("⚠️ Shikra.ini not found, using test configuration")
        host_url = 'http://localhost:8080/api/v1/'
        agent_id = 'agent-DESKTOP-Q6OSOEU-1003'  # From your registered agent
        agent_secret = 'secret-27279-12053'  # From your registered agent  
        poll_interval = 10  # Faster polling for testing
    
    if not agent_id or not agent_secret:
        print("❌ Missing agent_id or agent_secret in configuration")
        return
    
    # Create and run agent simulator
    agent = ShikraAgentSimulator(host_url, agent_id, agent_secret)
    agent.run_polling_loop(poll_interval)

if __name__ == "__main__":
    main()
