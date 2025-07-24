"""
Flask application factory for Shikra Host API
Handles agent communication and web dashboard
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import logging
import os
from datetime import datetime

from config.config import Config
from .routes.agents import agents_bp
from .routes.samples import samples_bp
from .routes.analysis import analysis_bp
from .routes.vm_management import vm_bp
from .routes.vm_config import vm_config_bp
from .routes.admin import admin_bp
from .routes.snapshots import snapshot_bp
from .routes.triggers import triggers_bp
from .routes.enrollment import enrollment_bp

logger = logging.getLogger(__name__)

def create_app():
    """Create and configure Flask application"""
    
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Enable CORS for dashboard
    CORS(app, origins=['http://localhost:*', 'http://127.0.0.1:*'])
    
    # Register blueprints
    app.register_blueprint(agents_bp, url_prefix='/api/v1/agent')
    app.register_blueprint(samples_bp, url_prefix='/api/v1/samples')
    app.register_blueprint(analysis_bp, url_prefix='/api/v1/analysis')
    app.register_blueprint(vm_bp, url_prefix='/api/v1/vm')
    app.register_blueprint(vm_config_bp, url_prefix='/api/v1/vm-config')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(snapshot_bp, url_prefix='/api/v1/snapshots')
    app.register_blueprint(triggers_bp, url_prefix='/api/v1/triggers')
    app.register_blueprint(enrollment_bp, url_prefix='/api/v1/enrollment')
    
    # Health check endpoint
    @app.route('/api/health')
    def health_check():
        """Simple health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0-mvp',
            'components': {
                'api': 'active',
                'storage': 'json-active'
            }
        })
    
    # Agent v2.0 compatibility - alias for polling endpoint
    @app.route('/api/v1/agents/next-sample', methods=['GET'])
    def agents_next_sample_alias():
        """Alias for /api/v1/samples/pending - Agent v2.0 compatibility"""
        from .routes.samples import get_pending_sample
        return get_pending_sample()
    
    # API documentation endpoint
    @app.route('/api/docs')
    def api_docs():
        """Simple API documentation"""
        docs = {
            'title': 'Shikra Host API',
            'version': '1.0.0-mvp',
            'description': 'REST API for malware analysis orchestration',
            'endpoints': {
                'Agent Communication': {
                    'POST /api/v1/agent/register': 'Register new agent with credentials',
                    'GET /api/v1/agent/next-sample': 'Get next sample for analysis',
                    'GET /api/v1/agent/download/{sample_id}': 'Download sample file',
                    'POST /api/v1/agent/status': 'Update analysis status',
                    'POST /api/v1/agent/upload/artifacts': 'Upload analysis artifacts',
                    'HEAD /api/v1/agent/health': 'Agent health check'
                },
                'Sample Management': {
                    'POST /api/v1/samples/upload': 'Upload new sample',
                    'GET /api/v1/samples': 'List samples',
                    'GET /api/v1/samples/{id}': 'Get sample details',
                    'DELETE /api/v1/samples/{id}': 'Delete sample',
                    'GET /api/v1/samples/pending': 'Get current or next pending sample (Bearer auth)',
                    'POST /api/v1/samples/{id}/results': 'Upload analysis results (multipart, Bearer auth)',
                    'POST /api/v1/samples/{id}/dump-trigger': 'Record memory dump trigger (Bearer auth)'
                },
                'VM Management': {
                    'POST /api/v1/vm/start': 'Start VM instance',
                    'POST /api/v1/vm/stop': 'Stop VM instance',
                    'POST /api/v1/vm/reset': 'Reset VM to clean state',
                    'GET /api/v1/vm/status': 'Get VM status'
                },
                'Analysis': {
                    'GET /api/v1/analysis': 'List analysis results',
                    'GET /api/v1/analysis/{id}': 'Get analysis details',
                    'POST /api/v1/analysis/{id}/trigger-dump': 'Trigger memory dump'
                }
            },
            'authentication': {
                'type': 'Bearer',
                'headers': {
                    'X-Agent-ID': 'Agent identifier',
                    'Authorization': 'Bearer <access_token>'
                }
            }
        }
        
        return jsonify(docs)
    
    # Dashboard route
    @app.route('/dashboard')
    @app.route('/dashboard/')
    @app.route('/dashboard/<path:path>')
    def dashboard(path=''):
        """Serve dashboard interface"""
        # For MVP, return simple HTML page
        # In production, this would serve a React/Vue.js application
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>Shikra Host Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .sub-card { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; border: 1px solid #dee2e6; }
        .status { padding: 10px; border-radius: 3px; margin: 10px 0; }
        .status.online { background: #d4edda; color: #155724; }
        .status.offline { background: #f8d7da; color: #721c24; }
        .button { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; margin: 5px; }
        .button:hover { background: #2980b9; }
        .button.danger { background: #e74c3c; }
        .button.danger:hover { background: #c0392b; }
        .button.success { background: #27ae60; }
        .button.success:hover { background: #229954; }
        #logs { background: #2c3e50; color: #ecf0f1; padding: 15px; height: 300px; overflow-y: scroll; font-family: monospace; font-size: 12px; }
        .upload-area { border: 2px dashed #bdc3c7; padding: 40px; text-align: center; border-radius: 5px; }
        
        /* VM Configuration Styles */
        .form-row { margin: 15px 0; }
        .form-row label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-row input, .form-row select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .form-row input[type="checkbox"] { width: auto; margin-right: 8px; }
        .form-row small { color: #666; font-size: 12px; }
        code { background: #f0f0f0; padding: 2px 4px; border-radius: 3px; font-size: 11px; }
        
        /* Modal Styles */
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); }
        .modal-content { background: white; margin: 5% auto; padding: 30px; border-radius: 10px; max-width: 700px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        .modal-header { border-bottom: 2px solid #27ae60; padding-bottom: 15px; margin-bottom: 20px; }
        .modal-close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .modal-close:hover { color: #000; }
        .key-display { background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; font-family: monospace; word-break: break-all; font-size: 14px; }
        .copy-btn { background: #27ae60; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 10px 5px; }
        .copy-btn:hover { background: #229954; }
        .copy-btn.copied { background: #3498db; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔬 Shikra Host Dashboard</h1>
        <p>Malware Analysis Orchestration System - MVP</p>
    </div>
    
    <div class="card">
        <h2>📊 System Status</h2>
        <div id="system-status">
            <div class="status offline">🤖 Agent: Checking...</div>
            <div class="status offline">💻 VM: Checking...</div>
            <div class="status online">🌐 API: Online</div>
            <div class="status online">💾 Database: Active</div>
        </div>
        <button class="button" onclick="refreshStatus()">🔄 Refresh Status</button>
    </div>
    
    <div class="card">
        <h2>📤 Sample Upload</h2>
        <div class="upload-area" onclick="document.getElementById('fileInput').click()">
            <p>Click here to upload a malware sample</p>
            <p style="font-size: 12px; color: #7f8c8d;">Supported: .exe, .dll, .scr, .com, .bat, .ps1, .vbs, .jar, .zip, .rar</p>
            <input type="file" id="fileInput" style="display: none;" onchange="uploadSample(this.files[0])">
        </div>
        <div id="upload-status"></div>
    </div>
    
    <div class="card">
        <h2>🤖 Registered Agents</h2>
        <div id="agents-list">Loading agents...</div>
        <button class="button" onclick="refreshAgents()">🔄 Refresh Agents</button>
    </div>
    
    <div class="card">
        <h2>🔬 Analysis Control</h2>
        <div id="snapshot-warning" style="display: none; background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #ffeaa7;">
            <strong>⚠️ Warning:</strong> No snapshot found for this VM! Create a clean snapshot before starting analysis to enable automatic recovery.
        </div>
        <div id="snapshot-info" style="display: none; background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin-bottom: 10px;">
            <strong>✅ Snapshot:</strong> <span id="current-snapshot-name"></span>
        </div>
        <button class="button success" onclick="startAnalysis()">▶️ Start Analysis</button>
        <button class="button danger" onclick="stopAnalysis()">⏹️ Stop Analysis</button>
        <button class="button" onclick="resetVM()">🔄 Reset VM</button>
        <button class="button" onclick="triggerDump()">💾 Trigger Memory Dump</button>
        <div id="analysis-status"></div>
    </div>
    
    <div class="card">
        <h2>📸 VM Snapshot Management</h2>
        <p>Snapshots allow quick VM recovery to clean state after analysis</p>
        
        <div class="form-row">
            <label for="vm-name-input">VM Name:</label>
            <input type="text" id="vm-name-input" placeholder="e.g., win10-analysis" value="">
            <small>Enter the libvirt VM name (virsh list --all)</small>
        </div>
        
        <div style="margin: 20px 0;">
            <button class="button" onclick="checkSnapshotStatus()">🔍 Check Snapshot Status</button>
            <button class="button success" onclick="createSnapshot()">📸 Create Snapshot</button>
            <button class="button" onclick="restoreSnapshot()">🔄 Restore to Snapshot</button>
            <button class="button" onclick="listSnapshots()">📋 List All Snapshots</button>
        </div>
        
        <div id="snapshot-status" style="margin-top: 15px;"></div>
        <div id="snapshot-list" style="margin-top: 15px;"></div>
    </div>
    
    <div class="card">
        <h2>📋 Recent Samples</h2>
        <div id="samples-list">Loading samples...</div>
        <button class="button" onclick="refreshSamples()">🔄 Refresh</button>
    </div>
    
    <div class="card">
        <h2>📝 Live Logs</h2>
        <div id="logs"></div>
        <button class="button" onclick="clearLogs()">🗑️ Clear Logs</button>
    </div>

    <!-- Agent Enrollment Section (Agent v2.0) -->
    <div class="card" id="enrollment-section">
        <h2>� Agent Enrollment (v2.0)</h2>
        <p style="background: #e3f2fd; padding: 10px; border-radius: 5px; border-left: 4px solid #2196f3;">
            <strong>ℹ️ Agent v2.0 Info:</strong> No INI files needed! Generate an enrollment key, deploy ShikraAgent.exe, and run enrollment command on Windows VM.
        </p>
        
        <!-- Available VMs -->
        <div class="sub-card">
            <h3>Available VMs (virsh list --all)</h3>
            <div id="vm-list-container">
                <p>Loading VMs from libvirt...</p>
            </div>
            <button class="button" onclick="refreshVMList()">🔄 Refresh VM List</button>
        </div>
        
        <!-- Enrollment Key Generator -->
        <div class="sub-card" id="enrollment-form-card" style="display: none;">
            <h3>Generate Enrollment Key for: <span id="selected-vm-name"></span></h3>
            <form id="enrollment-form">
                <input type="hidden" id="vm-name" name="vm_name">
                
                <div class="form-row">
                    <label for="vm-description">Description (optional):</label>
                    <input type="text" id="vm-description" name="description" 
                           placeholder="e.g., Windows 10 analysis VM">
                </div>
                
                <div class="form-row">
                    <label for="key-expiry">Enrollment Key Expiry:</label>
                    <select id="key-expiry" name="expires_in_days">
                        <option value="1">1 day</option>
                        <option value="7" selected>7 days</option>
                        <option value="14">14 days</option>
                        <option value="30">30 days</option>
                    </select>
                    <small>Key will expire and become unusable after this period</small>
                </div>
                
                <button type="submit" class="button success">� Generate Enrollment Key</button>
                <button type="button" onclick="cancelEnrollment()" class="button">❌ Cancel</button>
            </form>
        </div>
        
        <!-- Enrollment Keys List -->
        <div class="sub-card">
            <h3>Enrollment Keys</h3>
            <div id="enrollment-keys-list">
                <p>Loading enrollment keys...</p>
            </div>
            <button class="button" onclick="refreshEnrollmentKeys()">🔄 Refresh Keys</button>
        </div>
    </div>

    <script>
        let logCount = 0;
        
        function log(message, type = 'info') {
            const logs = document.getElementById('logs');
            const timestamp = new Date().toLocaleTimeString();
            const prefix = type === 'error' ? '❌' : type === 'success' ? '✅' : 'ℹ️';
            logs.innerHTML += `[${timestamp}] ${prefix} ${message}\\n`;
            logs.scrollTop = logs.scrollHeight;
            logCount++;
            if (logCount > 100) {
                const lines = logs.innerHTML.split('\\n');
                logs.innerHTML = lines.slice(-50).join('\\n');
                logCount = 50;
            }
        }
        
        function clearLogs() {
            document.getElementById('logs').innerHTML = '';
            logCount = 0;
        }
        
        async function apiCall(url, options = {}) {
            try {
                const response = await fetch(url, {
                    headers: {
                        'Content-Type': 'application/json',
                        ...options.headers
                    },
                    ...options
                });
                return await response.json();
            } catch (error) {
                log(`API Error: ${error.message}`, 'error');
                return null;
            }
        }
        
        async function refreshStatus() {
            log('Refreshing system status...');
            
            // Check API health
            const health = await apiCall('/api/health');
            if (health) {
                log('API health check successful', 'success');
            }
            
            // Check agent status
            const agentData = await apiCall('/api/v1/agent/list');
            const statusDiv = document.getElementById('system-status');
            
            if (agentData && agentData.agents) {
                const agentCount = Object.keys(agentData.agents).length;
                const activeAgents = Object.values(agentData.agents).filter(a => a.status === 'registered').length;
                
                statusDiv.innerHTML = `
                    <div class="status ${agentCount > 0 ? 'online' : 'offline'}">🤖 Agents: ${agentCount} registered (${activeAgents} active)</div>
                    <div class="status offline">💻 VM: Checking...</div>
                    <div class="status online">🌐 API: Online</div>
                    <div class="status online">💾 Storage: JSON Active</div>
                `;
                
                log(`Found ${agentCount} registered agents (${activeAgents} active)`, agentCount > 0 ? 'success' : 'info');
                
                // Show agent details
                if (agentCount > 0) {
                    Object.values(agentData.agents).forEach(agent => {
                        log(`Agent: ${agent.name} - Status: ${agent.status}`, 'info');
                    });
                }
            } else {
                statusDiv.innerHTML = `
                    <div class="status offline">🤖 Agents: Connection failed</div>
                    <div class="status offline">💻 VM: Unknown</div>
                    <div class="status online">🌐 API: Online</div>
                    <div class="status online">💾 Storage: JSON Active</div>
                `;
                log('Failed to get agent status', 'error');
            }
        }
        
        async function uploadSample(file) {
            if (!file) return;
            
            log(`Uploading sample: ${file.name} (${file.size} bytes)`);
            const uploadStatus = document.getElementById('upload-status');
            uploadStatus.innerHTML = `<p>Uploading ${file.name}...</p>`;
            
            const formData = new FormData();
            formData.append('sample', file);
            
            try {
                const response = await fetch('/api/v1/samples/upload', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    const result = await response.json();
                    log(`Sample uploaded successfully: ${result.sample_id}`, 'success');
                    uploadStatus.innerHTML = `<p style="color: green;">✅ Upload successful! Sample ID: ${result.sample_id}</p>`;
                    refreshSamples();
                } else {
                    const error = await response.json();
                    log(`Upload failed: ${error.error}`, 'error');
                    uploadStatus.innerHTML = `<p style="color: red;">❌ Upload failed: ${error.error}</p>`;
                }
            } catch (error) {
                log(`Upload error: ${error.message}`, 'error');
                uploadStatus.innerHTML = `<p style="color: red;">❌ Upload error: ${error.message}</p>`;
            }
        }
        
        async function startAnalysis() {
            log('Starting analysis...');
            
            // Check snapshot status first
            const vmName = document.getElementById('vm-name-input').value;
            if (vmName) {
                const snapshotStatus = await apiCall(`/api/v1/snapshots/status/${vmName}`);
                if (snapshotStatus && !snapshotStatus.has_snapshots) {
                    if (!confirm('⚠️ WARNING: No snapshot found for this VM! Continue without snapshot? (Not recommended)')) {
                        return;
                    }
                }
            }
            
            document.getElementById('analysis-status').innerHTML = '<p>🔄 Starting analysis...</p>';
        }
        
        async function stopAnalysis() {
            log('Stopping analysis...');
            document.getElementById('analysis-status').innerHTML = '<p>⏹️ Stopping analysis...</p>';
        }
        
        async function resetVM() {
            const vmName = document.getElementById('vm-name-input').value;
            if (!vmName) {
                alert('Please enter VM name');
                return;
            }
            
            log(`Restoring VM ${vmName} to clean snapshot...`);
            
            try {
                const response = await fetch('/api/v1/snapshots/restore', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({vm_name: vmName})
                });
                
                if (response.ok) {
                    const result = await response.json();
                    log(`VM restored successfully to ${result.snapshot_name}`, 'success');
                    alert(`✅ VM restored to snapshot: ${result.snapshot_name}`);
                } else {
                    const error = await response.json();
                    log(`Failed to restore VM: ${error.error}`, 'error');
                    alert(`❌ Failed to restore VM: ${error.error}`);
                }
            } catch (error) {
                log(`Error restoring VM: ${error.message}`, 'error');
                alert(`❌ Error: ${error.message}`);
            }
        }
        
        async function triggerDump() {
            log('Triggering memory dump...');
            // Placeholder - implement memory dump trigger
        }
        
        // Snapshot Management Functions
        
        async function checkSnapshotStatus() {
            const vmName = document.getElementById('vm-name-input').value;
            if (!vmName) {
                alert('Please enter VM name');
                return;
            }
            
            log(`Checking snapshot status for ${vmName}...`);
            const status = await apiCall(`/api/v1/snapshots/status/${vmName}`);
            const statusDiv = document.getElementById('snapshot-status');
            
            if (status) {
                const readyIcon = status.ready_for_analysis ? '✅' : '⚠️';
                const readyText = status.ready_for_analysis ? 'Ready for Analysis' : 'No Snapshots - Create one first!';
                const readyColor = status.ready_for_analysis ? 'green' : 'orange';
                
                statusDiv.innerHTML = `
                    <div style="border: 2px solid ${readyColor}; padding: 15px; border-radius: 5px; background: ${status.ready_for_analysis ? '#d4edda' : '#fff3cd'};">
                        <h3 style="margin: 0 0 10px 0;">${readyIcon} ${readyText}</h3>
                        <p><strong>VM:</strong> ${status.vm_name}</p>
                        <p><strong>Snapshot Count:</strong> ${status.snapshot_count}</p>
                        <p><strong>Current Snapshot:</strong> ${status.current_snapshot || 'None'}</p>
                    </div>
                `;
                
                // Update analysis control warning
                if (status.ready_for_analysis) {
                    document.getElementById('snapshot-warning').style.display = 'none';
                    document.getElementById('snapshot-info').style.display = 'block';
                    document.getElementById('current-snapshot-name').textContent = status.current_snapshot || 'Available';
                } else {
                    document.getElementById('snapshot-warning').style.display = 'block';
                    document.getElementById('snapshot-info').style.display = 'none';
                }
                
                log('Snapshot status retrieved', 'success');
            } else {
                statusDiv.innerHTML = '<p style="color: red;">Failed to get snapshot status</p>';
            }
        }
        
        async function createSnapshot() {
            const vmName = document.getElementById('vm-name-input').value;
            if (!vmName) {
                alert('Please enter VM name');
                return;
            }
            
            const snapshotName = prompt('Enter snapshot name (optional):', `clean_state_${new Date().toISOString().split('T')[0]}`);
            
            log(`Creating snapshot for ${vmName}...`);
            
            try {
                const response = await fetch('/api/v1/snapshots/create', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        vm_name: vmName,
                        snapshot_name: snapshotName,
                        description: `Clean state snapshot created at ${new Date().toLocaleString()}`
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    log(`Snapshot created: ${result.snapshot_name}`, 'success');
                    alert(`✅ Snapshot created successfully: ${result.snapshot_name}`);
                    checkSnapshotStatus();
                } else {
                    const error = await response.json();
                    log(`Failed to create snapshot: ${error.error}`, 'error');
                    alert(`❌ Failed to create snapshot: ${error.error}`);
                }
            } catch (error) {
                log(`Error creating snapshot: ${error.message}`, 'error');
                alert(`❌ Error: ${error.message}`);
            }
        }
        
        async function restoreSnapshot() {
            const vmName = document.getElementById('vm-name-input').value;
            if (!vmName) {
                alert('Please enter VM name');
                return;
            }
            
            if (!confirm(`Restore VM ${vmName} to the current snapshot?`)) {
                return;
            }
            
            log(`Restoring ${vmName} to snapshot...`);
            
            try {
                const response = await fetch('/api/v1/snapshots/restore', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({vm_name: vmName})
                });
                
                if (response.ok) {
                    const result = await response.json();
                    log(`Snapshot restored: ${result.snapshot_name}`, 'success');
                    alert(`✅ VM restored to snapshot: ${result.snapshot_name}`);
                } else {
                    const error = await response.json();
                    log(`Failed to restore snapshot: ${error.error}`, 'error');
                    alert(`❌ Failed to restore: ${error.error}`);
                }
            } catch (error) {
                log(`Error restoring snapshot: ${error.message}`, 'error');
                alert(`❌ Error: ${error.message}`);
            }
        }
        
        async function listSnapshots() {
            const vmName = document.getElementById('vm-name-input').value;
            if (!vmName) {
                alert('Please enter VM name');
                return;
            }
            
            log(`Listing snapshots for ${vmName}...`);
            const data = await apiCall(`/api/v1/snapshots/list/${vmName}`);
            const listDiv = document.getElementById('snapshot-list');
            
            if (data && data.snapshots) {
                if (data.snapshots.length === 0) {
                    listDiv.innerHTML = '<p>No snapshots found for this VM.</p>';
                } else {
                    listDiv.innerHTML = `
                        <h4>Snapshots (${data.count}):</h4>
                        ${data.snapshots.map(snap => `
                            <div style="border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 3px; background: #f9f9f9;">
                                <strong>📸 ${snap.name}</strong>
                                <br><small>Created: ${snap.creation_time || 'Unknown'}</small>
                                <br><small>State: ${snap.state || 'Unknown'}</small>
                            </div>
                        `).join('')}
                    `;
                    log(`Found ${data.count} snapshots`, 'success');
                }
            } else {
                listDiv.innerHTML = '<p style="color: red;">Failed to list snapshots</p>';
            }
        }
        
        async function refreshSamples() {
            log('Refreshing samples list...');
            const samples = await apiCall('/api/v1/samples');
            const samplesList = document.getElementById('samples-list');
            
            if (samples && samples.samples) {
                if (samples.samples.length === 0) {
                    samplesList.innerHTML = '<p>No samples uploaded yet.</p>';
                } else {
                    samplesList.innerHTML = samples.samples.map(sample => `
                        <div style="border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 3px;">
                            <strong>${sample.filename}</strong> - ${sample.status}
                            <br><small>Hash: ${sample.file_hash}</small>
                            <br><small>Uploaded: ${new Date(sample.uploaded_at).toLocaleString()}</small>
                        </div>
                    `).join('');
                }
            } else {
                samplesList.innerHTML = '<p>Error loading samples.</p>';
            }
        }
        
        async function refreshAgents() {
            log('Refreshing agents list...');
            const agentData = await apiCall('/api/v1/agent/list');
            const agentsList = document.getElementById('agents-list');
            
            if (agentData && agentData.agents) {
                const agents = Object.values(agentData.agents);
                if (agents.length === 0) {
                    agentsList.innerHTML = '<p>No agents registered yet.</p>';
                } else {
                    agentsList.innerHTML = agents.map(agent => `
                        <div style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #f9f9f9;">
                            <h4 style="margin: 0 0 10px 0; color: #2c3e50;">🤖 ${agent.name}</h4>
                            <p><strong>Status:</strong> <span style="color: ${agent.status === 'registered' ? 'green' : 'red'};">${agent.status}</span></p>
                            <p><strong>Capabilities:</strong> ${agent.capabilities}</p>
                            <p><strong>Working Directory:</strong> ${agent.working_directory}</p>
                            <p><strong>Poll Interval:</strong> ${agent.poll_interval}ms</p>
                            <p><strong>Registered:</strong> ${new Date(agent.registered_at).toLocaleString()}</p>
                            <p><strong>Last Updated:</strong> ${new Date(agent.last_updated).toLocaleString()}</p>
                        </div>
                    `).join('');
                    log(`Loaded ${agents.length} agents`, 'success');
                }
            } else {
                agentsList.innerHTML = '<p>Error loading agents.</p>';
                log('Failed to load agents', 'error');
            }
        }
        
        // Initialize dashboard
        log('Shikra Host Dashboard initialized', 'success');
        
        // Auto-refresh on load
        refreshAgents();
        refreshSamples();
        
        // Load VM name from localStorage if available
        const savedVmName = localStorage.getItem('vm_name');
        if (savedVmName) {
            document.getElementById('vm-name-input').value = savedVmName;
            checkSnapshotStatus();
        }
        
        // Save VM name when it changes
        document.getElementById('vm-name-input').addEventListener('change', function() {
            localStorage.setItem('vm_name', this.value);
        });
        refreshStatus();
        refreshSamples();
        refreshAgents();
        
        // Load enrollment keys
        refreshVMList();
        refreshEnrollmentKeys();
        
        // Auto-refresh every 5 seconds
        setInterval(() => {
            refreshStatus();
            refreshAgents();
        }, 5000);

        // Enrollment Management Functions
        async function refreshVMList() {
            try {
                log('Loading VMs from libvirt...');
                const response = await fetch('/api/v1/vm-config/vms');
                const data = await response.json();
                
                const container = document.getElementById('vm-list-container');
                if (data.success && data.vms.length > 0) {
                    container.innerHTML = `
                        <table style="width: 100%; border-collapse: collapse; margin: 10px 0;">
                            <thead>
                                <tr style="background: #f0f0f0;">
                                    <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">VM Name</th>
                                    <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">State</th>
                                    <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Status</th>
                                    <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${data.vms.map(vm => `
                                    <tr>
                                        <td style="padding: 8px; border: 1px solid #ddd;"><strong>${vm.name}</strong></td>
                                        <td style="padding: 8px; border: 1px solid #ddd;">${vm.state}</td>
                                        <td style="padding: 8px; border: 1px solid #ddd;">
                                            ${vm.configured ? '<span style="color: green;">✓ Configured</span>' : '<span style="color: gray;">Not Configured</span>'}
                                        </td>
                                        <td style="padding: 8px; border: 1px solid #ddd;">
                                            <button onclick="createConfig('${vm.name}')" class="button" style="padding: 4px 8px; font-size: 12px;">
                                                ${vm.configured ? '⚙️ Reconfigure' : '➕ Create Config'}
                                            </button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    `;
                    log(`Found ${data.vms.length} VMs from libvirt`, 'success');
                } else if (data.success && data.vms.length === 0) {
                    container.innerHTML = '<p>No VMs found. Make sure libvirt/virsh is available and VMs exist.</p>';
                    log('No VMs found in libvirt', 'info');
                } else {
                    container.innerHTML = '<p>Error: ' + (data.error || 'Unknown error') + '</p>';
                    log('Failed to load VMs: ' + (data.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                document.getElementById('vm-list-container').innerHTML = '<p>Error loading VMs: ' + error.message + '</p>';
                log('VM list error: ' + error.message, 'error');
            }
        }

        function createConfig(vmName) {
            // Show enrollment form
            document.getElementById('enrollment-form-card').style.display = 'block';
            document.getElementById('selected-vm-name').textContent = vmName;
            document.getElementById('vm-name').value = vmName;
            document.getElementById('vm-description').value = `${vmName} analysis VM`;
            
            // Scroll to form
            document.getElementById('enrollment-form-card').scrollIntoView();
            log(`Generating enrollment key for VM: ${vmName}`, 'info');
        }

        function cancelEnrollment() {
            document.getElementById('enrollment-form-card').style.display = 'none';
            document.getElementById('enrollment-form').reset();
            log('Enrollment form cancelled', 'info');
        }

        // Handle enrollment form submission
        document.getElementById('enrollment-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const enrollmentData = {
                vm_name: formData.get('vm_name'),
                description: formData.get('description') || `${formData.get('vm_name')} analysis VM`,
                expires_in_days: parseInt(formData.get('expires_in_days'))
            };
            
            log(`Generating enrollment key for ${enrollmentData.vm_name}...`);
            
            try {
                const response = await fetch('/api/v1/enrollment/keys/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(enrollmentData)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    log(`Enrollment key generated for ${result.vm_name}`, 'success');
                    
                    // Store key for modal
                    window.currentEnrollmentKey = result.enrollment_key;
                    
                    // Show modal with key details
                    showEnrollmentKeyModal(result);
                    
                    // Reset and hide form
                    cancelEnrollment();
                    
                    // Refresh lists
                    refreshVMList();
                    refreshEnrollmentKeys();
                } else {
                    log('Failed to generate enrollment key: ' + (result.error || 'Unknown error'), 'error');
                    alert('Failed to generate enrollment key: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                log('Enrollment key generation error: ' + error.message, 'error');
                alert('Error generating enrollment key: ' + error.message);
            }
        });

        function showEnrollmentKeyModal(result) {
            const modalInfo = document.getElementById('modalKeyInfo');
            modalInfo.innerHTML = `
                <div style="margin: 20px 0;">
                    <p><strong>VM Name:</strong> ${result.vm_name}</p>
                    <p><strong>Agent ID:</strong> ${result.agent_id}</p>
                    <p><strong>Expires:</strong> ${new Date(result.expires_at).toLocaleString()}</p>
                </div>
                
                <h3 style="margin-top: 20px;">Enrollment Key:</h3>
                <div class="key-display" id="enrollmentKeyText">${result.enrollment_key}</div>
                
                <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin-top: 20px;">
                    <h4 style="margin-top: 0;">📋 Deployment Steps:</h4>
                    <ol style="margin: 10px 0; padding-left: 20px;">
                        <li>Copy ShikraAgent.exe to Windows VM (e.g., C:\\SecurityHealth\\)</li>
                        <li>Open CMD as Administrator</li>
                        <li>Run: <code style="background: #fff; padding: 4px 8px; border-radius: 3px;">ShikraAgent.exe --enroll ${result.enrollment_key}</code></li>
                        <li>Enter Shost URL when prompted: <code style="background: #fff; padding: 4px 8px; border-radius: 3px;">http://192.168.100.1:8080/api/v1</code></li>
                        <li>Start agent: <code style="background: #fff; padding: 4px 8px; border-radius: 3px;">ShikraAgent.exe</code></li>
                    </ol>
                    <p style="margin: 10px 0; font-size: 12px; color: #666;">
                        The agent will automatically create <code>C:\\SecurityHealth\\agent_config.json</code>
                    </p>
                </div>
            `;
            
            document.getElementById('enrollmentKeyModal').style.display = 'block';
        }

        function closeKeyModal() {
            document.getElementById('enrollmentKeyModal').style.display = 'none';
            window.currentEnrollmentKey = null;
        }

        function copyEnrollmentKey() {
            const key = window.currentEnrollmentKey;
            if (!key) {
                alert('No key to copy');
                return;
            }
            
            navigator.clipboard.writeText(key).then(() => {
                const btn = document.getElementById('copyKeyBtn');
                btn.textContent = '✅ Copied!';
                btn.classList.add('copied');
                log('Enrollment key copied to clipboard', 'success');
                
                setTimeout(() => {
                    btn.textContent = '📋 Copy Enrollment Key';
                    btn.classList.remove('copied');
                }, 2000);
            }).catch(err => {
                alert('Failed to copy key: ' + err);
            });
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('enrollmentKeyModal');
            if (event.target == modal) {
                closeKeyModal();
            }
        }

        async function refreshEnrollmentKeys() {
            try {
                log('Loading enrollment keys...');
                const response = await fetch('/api/v1/enrollment/keys/list');
                const data = await response.json();
                
                const keysList = document.getElementById('enrollment-keys-list');
                
                if (data.enrollment_keys && data.enrollment_keys.length > 0) {
                    keysList.innerHTML = data.enrollment_keys.map(key => {
                        const statusBadge = key.used ? '✅ Enrolled' : key.status === 'revoked' ? '❌ Revoked' : '⏳ Pending';
                        const statusColor = key.used ? '#27ae60' : key.status === 'revoked' ? '#e74c3c' : '#f39c12';
                        
                        return `
                        <div style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #f9f9f9;">
                            <h4 style="margin: 0 0 10px 0;">🖥️ ${key.vm_name}</h4>
                            <p><strong>Agent ID:</strong> ${key.agent_id}</p>
                            <p><strong>Description:</strong> ${key.description || 'N/A'}</p>
                            <p><strong>Status:</strong> <span style="background: ${statusColor}; color: white; padding: 4px 8px; border-radius: 3px;">${statusBadge}</span></p>
                            <p><strong>Created:</strong> ${new Date(key.created).toLocaleString()}</p>
                            ${key.used && key.enrolled_hostname ? `<p><strong>Enrolled Hostname:</strong> ${key.enrolled_hostname}</p>` : ''}
                            ${!key.used && key.status !== 'revoked' ? `
                                <button onclick="revokeKey('${key.agent_id}')" class="button danger" style="padding: 4px 8px; margin: 2px; font-size: 12px;">
                                    �️ Revoke Key
                                </button>
                            ` : ''}
                        </div>
                    `}).join('');
                    log(`Loaded ${data.enrollment_keys.length} enrollment keys`, 'success');
                } else {
                    keysList.innerHTML = '<p>No enrollment keys created yet.</p>';
                    log('No enrollment keys found', 'info');
                }
            } catch (error) {
                document.getElementById('enrollment-keys-list').innerHTML = '<p>Error loading enrollment keys.</p>';
                log('Enrollment keys list error: ' + error.message, 'error');
            }
        }

        async function revokeKey(agentId) {
            if (!confirm(`Revoke enrollment key for ${agentId}?`)) return;
            
            try {
                const response = await fetch(`/api/v1/enrollment/keys/${agentId}/revoke`, {
                    method: 'POST'
                });
                const result = await response.json();
                
                if (result.success) {
                    log(`Enrollment key revoked for ${agentId}`, 'success');
                    refreshEnrollmentKeys();
                } else {
                    alert('Failed to revoke key: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                log('Revoke key error: ' + error.message, 'error');
            }
        }
    </script>

    <!-- Enrollment Key Modal -->
    <div id="enrollmentKeyModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="modal-close" onclick="closeKeyModal()">&times;</span>
                <h2 style="margin: 0; color: #27ae60;">🔑 Enrollment Key Generated!</h2>
            </div>
            
            <p style="background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;">
                <strong>⚠️ IMPORTANT:</strong> This key will <strong>only be shown once</strong>. Copy it now!
            </p>
            
            <div id="modalKeyInfo"></div>
            
            <div style="text-align: center; margin-top: 20px;">
                <button class="copy-btn" onclick="copyEnrollmentKey()" id="copyKeyBtn">
                    📋 Copy Enrollment Key
                </button>
                <button class="button" onclick="closeKeyModal()" style="padding: 12px 24px;">
                    ✅ Done
                </button>
            </div>
        </div>
    </div>

</body>
</html>
        '''
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500
    
    # Request logging
    @app.before_request
    def log_request():
        logger.info(f"{request.method} {request.path} from {request.remote_addr}")
    
    return app
