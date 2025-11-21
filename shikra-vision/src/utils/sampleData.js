// Sample data based on the schemas
export const sampleMemoryData = {
  "metadata": {
    "analysis_timestamp": "2024-07-20T10:30:00Z",
    "volatility_version": "3.2.0",
    "analyzer_version": "1.5.2",
    "memory_image": {
      "filename": "infected_workstation.vmem",
      "size": 8589934592,
      "hash": {
        "md5": "a1b2c3d4e5f6789012345678901234567",
        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
      },
      "acquisition_time": "2024-07-20T09:45:23Z"
    },
    "system_info": {
      "os": "Windows 10 22H2",
      "architecture": "AMD64",
      "kernel_version": "10.0.19045",
      "build": "19045.3324",
      "hostname": "INFECTED-PC",
      "timezone": "UTC-5"
    },
    "plugins_executed": [
      {
        "plugin": "windows.pslist",
        "execution_time": "2.3s",
        "status": "success",
        "records_found": 127
      },
      {
        "plugin": "windows.malfind", 
        "execution_time": "45.2s",
        "status": "success",
        "records_found": 8
      }
    ],
    "integrations": {
      "virustotal": {
        "enabled": true,
        "api_calls": 43,
        "rate_limit_remaining": 957
      },
      "maxmind_geoip": {
        "enabled": true,
        "database_version": "2024-07-15",
        "lookups_performed": 67
      }
    }
  },
  "analysis_results": {
    "processes": [
      {
        "pid": 1234,
        "ppid": 812,
        "name": "malicious.exe",
        "offset": "0x87654321",
        "create_time": "2024-07-20T09:30:15Z",
        "exit_time": null,
        "session_id": 1,
        "wow64": false,
        "command_line": "malicious.exe -silent -config c:\\temp\\evil.cfg",
        "executable_path": "C:\\Temp\\malicious.exe",
        "user": "WORKSTATION\\victim",
        "integrity_level": "medium",
        "process_ancestry": [
          {"pid": 812, "name": "explorer.exe", "create_time": "2024-07-20T09:00:00Z"},
          {"pid": 456, "name": "winlogon.exe", "create_time": "2024-07-20T08:55:00Z"}
        ],
        "threads": [
          {
            "tid": 5678,
            "start_address": "0x140001000",
            "create_time": "2024-07-20T09:30:16Z",
            "state": "running",
            "win32_start_address": "kernel32.dll!BaseThreadInitThunk"
          }
        ],
        "handles": [
          {
            "handle_value": 124,
            "type": "File",
            "name": "\\Device\\HarddiskVolume3\\Windows\\System32\\advapi32.dll",
            "access": "0x120089"
          }
        ],
        "vad_info": {
          "vad_count": 47,
          "executable_vads": 12,
          "private_memory": 8388608,
          "mapped_files": [
            {
              "base_address": "0x140000000",
              "size": 2048576,
              "protection": "PAGE_EXECUTE_READ",
              "filename": "C:\\Temp\\malicious.exe"
            }
          ]
        },
        "dll_list": [
          {
            "base_address": "0x140000000",
            "size": 2048576,
            "name": "malicious.exe",
            "path": "C:\\Temp\\malicious.exe",
            "load_time": "2024-07-20T09:30:15Z",
            "hash": {
              "md5": "5d41402abc4b2a76b9719d911017c592",
              "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
            },
            "digital_signature": {
              "signed": false,
              "valid": false,
              "signer": null
            },
            "version_info": {
              "company_name": "",
              "file_description": "",
              "file_version": ""
            },
            "virustotal": {
              "detection_ratio": "45/71",
              "scan_date": "2024-07-19T14:22:33Z",
              "permalink": "https://www.virustotal.com/gui/file/2c26b46...",
              "verdict": "malicious",
              "engines": [
                {"engine": "Microsoft", "result": "Trojan:Win32/GenKryptik.ABCD"},
                {"engine": "Kaspersky", "result": "HEUR:Trojan.Win32.Generic"}
              ]
            }
          }
        ],
        "network_artifacts": [
          {
            "connection_type": "tcp",
            "local_address": "192.168.1.100",
            "local_port": 49152,
            "remote_address": "185.220.101.45",
            "remote_port": 443,
            "state": "ESTABLISHED",
            "create_time": "2024-07-20T09:32:00Z",
            "geoip": {
              "country": "Russian Federation",
              "country_code": "RU", 
              "city": "Moscow",
              "latitude": 55.7558,
              "longitude": 37.6176,
              "asn": "AS12345",
              "organization": "Evil Hosting Ltd",
              "is_tor": false,
              "is_vpn": true,
              "threat_categories": ["malware", "c2"]
            }
          }
        ],
        "anomalies": [
          {
            "type": "unsigned_executable",
            "severity": "medium",
            "description": "Process running unsigned executable"
          },
          {
            "type": "suspicious_network",
            "severity": "high", 
            "description": "Connection to known C2 infrastructure"
          }
        ]
      }
    ],
    "network_connections": [
      {
        "protocol": "tcp",
        "local_address": "192.168.1.100",
        "local_port": 49152,
        "remote_address": "185.220.101.45", 
        "remote_port": 443,
        "state": "ESTABLISHED",
        "pid": 1234,
        "process_name": "malicious.exe",
        "create_time": "2024-07-20T09:32:00Z",
        "geoip": {
          "country": "Russian Federation",
          "country_code": "RU",
          "region": "Moscow",
          "city": "Moscow",
          "postal_code": "101000",
          "latitude": 55.7558,
          "longitude": 37.6176,
          "timezone": "Europe/Moscow",
          "asn": "AS12345",
          "organization": "Evil Hosting Ltd",
          "isp": "Evil ISP",
          "is_anonymous_proxy": false,
          "is_satellite": false,
          "connection_type": "Cable/DSL"
        },
        "threat_intel": {
          "reputation": "malicious",
          "categories": ["c2", "malware"],
          "first_seen": "2024-06-15T00:00:00Z",
          "confidence": 95
        }
      }
    ],
    "malware_analysis": {
      "malfind_results": [
        {
          "pid": 1234,
          "process_name": "malicious.exe",
          "address": "0x2a0000",
          "size": 4096,
          "protection": "PAGE_EXECUTE_READWRITE",
          "commit_charge": "VadS",
          "privatememory": 1,
          "tag": "VadS",
          "disassembly": [
            "0x2a0000: mov eax, 0x12345678",
            "0x2a0005: call 0x2a0010",
            "0x2a000a: jmp 0x2a0020"
          ],
          "hexdump": "B878563412E8010000EB14...",
          "yara_matches": [
            {
              "rule": "Win32_Trojan_Generic",
              "namespace": "default", 
              "strings": [
                {"identifier": "$api_call", "offset": 25, "data": "GetProcAddress"}
              ]
            }
          ],
          "entropy": 7.8,
          "pe_characteristics": {
            "is_pe": true,
            "has_relocations": false,
            "is_stripped": true
          }
        }
      ],
      "code_injection": [
        {
          "injector_pid": 1234,
          "injector_name": "malicious.exe",
          "target_pid": 2468,
          "target_name": "explorer.exe", 
          "injection_type": "process_hollowing",
          "injected_address": "0x400000",
          "injected_size": 65536,
          "detection_confidence": 0.95
        }
      ],
      "rootkit_artifacts": [
        {
          "type": "hidden_process",
          "pid": 6666,
          "name": "rootkit.exe",
          "hiding_technique": "dkom_manipulation",
          "evidence": "Process present in PsActiveProcessHead but missing from handle table"
        }
      ]
    },
    "registry_analysis": [
      {
        "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "key": "Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "EvilPersistence",
        "value_data": "C:\\Temp\\malicious.exe --autostart",
        "value_type": "REG_SZ",
        "last_write_time": "2024-07-20T09:31:00Z",
        "persistence_technique": "registry_autorun"
      }
    ],
    "file_artifacts": [
      {
        "filename": "evil.cfg",
        "full_path": "C:\\Temp\\evil.cfg",
        "size": 1024,
        "allocation_status": "allocated",
        "resident": true,
        "hash": {
          "md5": "098f6bcd4621d373cade4e832627b4f6",
          "sha256": "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f"
        },
        "created": "2024-07-20T09:31:15Z",
        "modified": "2024-07-20T09:31:15Z",
        "accessed": "2024-07-20T09:32:00Z",
        "virustotal": {
          "detection_ratio": "0/71",
          "scan_date": "2024-07-20T10:30:00Z",
          "verdict": "clean"
        }
      }
    ],
    "memory_regions": [
      {
        "base_address": "0x2a0000",
        "size": 4096,
        "protection": "PAGE_EXECUTE_READWRITE", 
        "type": "MEM_PRIVATE",
        "state": "MEM_COMMIT",
        "pid": 1234,
        "process_name": "malicious.exe",
        "content_type": "shellcode",
        "entropy": 7.8,
        "strings": [
          {"offset": 45, "data": "http://evil.com/beacon", "encoding": "ascii"},
          {"offset": 128, "data": "GetProcAddress", "encoding": "ascii"}
        ]
      }
    ]
  },
  "threat_assessment": {
    "overall_risk_score": 9.2,
    "confidence": 0.95,
    "threat_categories": ["malware", "c2_communication", "persistence", "code_injection"],
    "iocs": [
      {
        "type": "hash",
        "value": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        "context": "malicious.exe SHA256"
      },
      {
        "type": "ip",
        "value": "185.220.101.45", 
        "context": "C2 server communication"
      },
      {
        "type": "registry",
        "value": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilPersistence",
        "context": "Persistence mechanism"
      }
    ],
    "mitre_tactics": [
      {"tactic": "T1055", "technique": "Process Injection", "evidence": ["code_injection_detected"]},
      {"tactic": "T1547.001", "technique": "Registry Run Keys", "evidence": ["registry_persistence"]},
      {"tactic": "T1071.001", "technique": "Web Protocols", "evidence": ["https_c2_communication"]}
    ],
    "timeline": [
      {
        "timestamp": "2024-07-20T09:30:15Z",
        "event": "Process creation: malicious.exe",
        "severity": "high"
      },
      {
        "timestamp": "2024-07-20T09:31:00Z", 
        "event": "Registry persistence established",
        "severity": "high"
      },
      {
        "timestamp": "2024-07-20T09:32:00Z",
        "event": "C2 communication initiated",
        "severity": "critical"
      }
    ]
  },
  "recommendations": [
    {
      "priority": "immediate",
      "action": "isolate_system",
      "rationale": "Active C2 communication detected"
    },
    {
      "priority": "high",
      "action": "block_c2_ip",
      "target": "185.220.101.45",
      "rationale": "Known malicious infrastructure"
    },
    {
      "priority": "high", 
      "action": "remove_persistence",
      "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilPersistence",
      "rationale": "Malware persistence mechanism"
    }
  ]
}

export const sampleNetworkData = {
  "metadata": {
    "analysis_timestamp": "2024-07-20T10:30:00Z",
    "analyzer_version": "2.1.0",
    "tshark_version": "4.0.8",
    "pcap_info": {
      "filename": "network_capture.pcapng",
      "file_size": 134217728,
      "hash": {
        "md5": "a1b2c3d4e5f6789012345678901234567",
        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
      },
      "capture_start": "2024-07-20T09:00:00Z",
      "capture_end": "2024-07-20T10:00:00Z",
      "duration": 3600,
      "interface": "eth0",
      "link_type": "Ethernet",
      "snaplen": 65535
    },
    "analysis_config": {
      "geoip_enabled": true,
      "threat_intel_enabled": true,
      "dns_analysis": true,
      "tls_analysis": true,
      "http_analysis": true,
      "file_extraction": true,
      "protocol_anomaly_detection": true
    },
    "statistics": {
      "total_packets": 245789,
      "total_bytes": 134217728,
      "unique_flows": 1247,
      "protocols": {
        "tcp": 189456,
        "udp": 45123,
        "icmp": 987,
        "dns": 8934,
        "http": 12456,
        "https": 23789,
        "smtp": 567,
        "other": 2477
      }
    },
    "integrations": {
      "maxmind_geoip": {
        "enabled": true,
        "database_version": "2024-07-15",
        "lookups_performed": 2847
      },
      "threat_intelligence": {
        "sources": ["virustotal", "abuseipdb", "otx"],
        "api_calls": 156,
        "hits": 23
      }
    }
  },
  "network_flows": [
    {
      "flow_id": "flow_001_tcp_192.168.1.100_49152_185.220.101.45_443",
      "protocol": "tcp",
      "src_ip": "192.168.1.100",
      "src_port": 49152,
      "dst_ip": "185.220.101.45",
      "dst_port": 443,
      "start_time": "2024-07-20T09:15:30.123Z",
      "end_time": "2024-07-20T09:45:22.456Z",
      "duration": 1792.333,
      "packets_sent": 147,
      "packets_received": 203,
      "bytes_sent": 45678,
      "bytes_received": 123456,
      "flow_state": "established",
      "flags": ["SYN", "ACK", "PSH", "FIN"],
      "tcp_analysis": {
        "handshake_rtt": 0.045,
        "retransmissions": 3,
        "out_of_order": 1,
        "window_scaling": true,
        "mss": 1460,
        "sack_permitted": true
      },
      "application_layer": {
        "detected_protocol": "tls",
        "tls_info": {
          "version": "TLSv1.3",
          "cipher_suite": "TLS_AES_256_GCM_SHA384",
          "server_name": "malicious-c2.com",
          "certificate": {
            "subject": "CN=malicious-c2.com",
            "issuer": "CN=Let's Encrypt Authority X3",
            "serial": "03A2F4B8E9C7D6A1",
            "valid_from": "2024-06-01T00:00:00Z",
            "valid_to": "2024-09-01T00:00:00Z",
            "fingerprint_sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            "is_self_signed": false,
            "is_expired": false
          },
          "ja3_fingerprint": "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11-13-23,23-24-25,0",
          "ja3s_fingerprint": "769,47,0-23"
        }
      },
      "geoip": {
        "src_geo": {
          "country": "United States",
          "country_code": "US",
          "region": "California",
          "city": "San Francisco",
          "latitude": 37.7749,
          "longitude": -122.4194,
          "asn": "AS7922",
          "organization": "Comcast Cable Communications"
        },
        "dst_geo": {
          "country": "Russian Federation",
          "country_code": "RU",
          "region": "Moscow",
          "city": "Moscow", 
          "latitude": 55.7558,
          "longitude": 37.6176,
          "asn": "AS12345",
          "organization": "Evil Hosting Ltd",
          "is_tor": false,
          "is_vpn": true,
          "threat_categories": ["malware", "c2"]
        }
      },
      "threat_intel": {
        "src_reputation": "clean",
        "dst_reputation": "malicious",
        "dst_categories": ["c2", "malware", "botnet"],
        "confidence": 95,
        "sources": ["virustotal", "abuseipdb"],
        "first_seen": "2024-06-15T00:00:00Z",
        "reports": [
          {
            "source": "virustotal",
            "verdict": "malicious", 
            "detection_ratio": "15/89",
            "categories": ["c2-server"]
          }
        ]
      },
      "anomalies": [
        {
          "type": "suspicious_destination",
          "severity": "high",
          "description": "Connection to known C2 infrastructure"
        },
        {
          "type": "unusual_traffic_pattern",
          "severity": "medium", 
          "description": "Regular beacon-like traffic pattern detected"
        }
      ],
      "extracted_files": [
        {
          "filename": "payload.exe",
          "size": 2048576,
          "protocol": "http",
          "hash": {
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
          },
          "mime_type": "application/x-msdownload",
          "extracted_path": "/tmp/extracted_files/payload.exe",
          "threat_intel": {
            "virustotal": {
              "detection_ratio": "45/71",
              "verdict": "malicious",
              "scan_date": "2024-07-19T14:22:33Z"
            }
          }
        }
      ]
    }
  ],
  "dns_analysis": [
    {
      "query_id": "dns_001",
      "timestamp": "2024-07-20T09:15:25.789Z",
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "query_name": "malicious-c2.com",
      "query_type": "A",
      "response_code": "NOERROR",
      "responses": [
        {
          "name": "malicious-c2.com",
          "type": "A",
          "ttl": 300,
          "data": "185.220.101.45"
        }
      ],
      "query_flags": ["RD", "RA"],
      "response_time": 0.125,
      "threat_intel": {
        "domain_reputation": "malicious",
        "categories": ["c2", "malware"],
        "first_seen": "2024-06-10T00:00:00Z",
        "dga_probability": 0.15,
        "entropy": 3.2
      },
      "anomalies": [
        {
          "type": "suspicious_domain",
          "severity": "high",
          "description": "Domain associated with known malware family"
        }
      ]
    }
  ],
  "http_analysis": [
    {
      "request_id": "http_001", 
      "timestamp": "2024-07-20T09:20:15.456Z",
      "src_ip": "192.168.1.100",
      "dst_ip": "203.0.113.45",
      "method": "GET",
      "uri": "/download/payload.exe",
      "host": "download.evil.com",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "referer": "https://malicious-site.com/landing",
      "request_headers": {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive"
      },
      "response_code": 200,
      "response_headers": {
        "Content-Type": "application/octet-stream",
        "Content-Length": "2048576",
        "Content-Disposition": "attachment; filename=payload.exe"
      },
      "response_size": 2048576,
      "extracted_files": ["payload.exe"],
      "threat_intel": {
        "url_reputation": "malicious",
        "categories": ["malware_download"],
        "confidence": 90
      },
      "anomalies": [
        {
          "type": "malware_download",
          "severity": "critical",
          "description": "Executable file download from suspicious domain"
        }
      ]
    }
  ],
  "email_analysis": [
    {
      "email_id": "smtp_001",
      "timestamp": "2024-07-20T09:10:30.123Z",
      "protocol": "smtp",
      "src_ip": "192.168.1.100",
      "dst_ip": "203.0.113.25",
      "from": "victim@company.com",
      "to": ["attacker@evil.com"],
      "subject": "Confidential Financial Data",
      "message_id": "<abc123@company.com>",
      "attachments": [
        {
          "filename": "financial_data.xlsx",
          "size": 45678,
          "hash": {
            "md5": "098f6bcd4621d373cade4e832627b4f6",
            "sha256": "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f"
          },
          "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
      ],
      "threat_intel": {
        "sender_reputation": "clean",
        "recipient_reputation": "suspicious", 
        "domain_reputation": "malicious"
      },
      "anomalies": [
        {
          "type": "data_exfiltration",
          "severity": "high",
          "description": "Sensitive data sent to external suspicious domain"
        }
      ]
    }
  ],
  "protocol_anomalies": [
    {
      "anomaly_id": "proto_001",
      "timestamp": "2024-07-20T09:25:45.789Z",
      "type": "port_scan",
      "src_ip": "10.0.0.50",
      "target_range": "192.168.1.0/24",
      "ports_scanned": [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 993, 995],
      "scan_duration": 120,
      "packets_count": 240,
      "detection_confidence": 0.95,
      "severity": "medium"
    },
    {
      "anomaly_id": "proto_002",
      "timestamp": "2024-07-20T09:30:12.456Z", 
      "type": "dns_tunneling",
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "suspicious_domains": [
        "a1b2c3d4e5.tunnel.evil.com",
        "f6g7h8i9j0.tunnel.evil.com"
      ],
      "query_frequency": 50,
      "average_query_size": 240,
      "detection_confidence": 0.85,
      "severity": "high"
    }
  ],
  "threat_hunting": {
    "beaconing_analysis": [
      {
        "src_ip": "192.168.1.100",
        "dst_ip": "185.220.101.45",
        "beacon_score": 0.92,
        "interval_consistency": 0.89,
        "size_consistency": 0.87,
        "average_interval": 60.5,
        "jitter": 5.2,
        "total_beacons": 47,
        "first_beacon": "2024-07-20T09:15:30Z",
        "last_beacon": "2024-07-20T09:45:22Z"
      }
    ],
    "lateral_movement": [
      {
        "src_ip": "192.168.1.100",
        "targets": ["192.168.1.101", "192.168.1.102", "192.168.1.103"],
        "protocols": ["smb", "rdp", "wmi"],
        "authentication_attempts": 15,
        "successful_connections": 2,
        "time_window": "2024-07-20T09:20:00Z to 2024-07-20T09:35:00Z"
      }
    ],
    "data_exfiltration": [
      {
        "src_internal": "192.168.1.100",
        "dst_external": "203.0.113.45",
        "protocols": ["smtp", "http", "ftp"],
        "total_bytes": 50331648,
        "file_types": ["xlsx", "docx", "pdf"],
        "encryption_detected": false,
        "compression_detected": true
      }
    ]
  },
  "iocs": [
    {
      "type": "ip",
      "value": "185.220.101.45",
      "context": "C2 server communication",
      "confidence": 95,
      "first_seen": "2024-07-20T09:15:30Z"
    },
    {
      "type": "domain", 
      "value": "malicious-c2.com",
      "context": "C2 domain resolution",
      "confidence": 90,
      "first_seen": "2024-07-20T09:15:25Z"
    },
    {
      "type": "hash",
      "value": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
      "context": "Downloaded malware payload",
      "confidence": 100,
      "first_seen": "2024-07-20T09:20:15Z"
    },
    {
      "type": "ja3",
      "value": "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11-13-23,23-24-25,0",
      "context": "TLS client fingerprint",
      "confidence": 85,
      "first_seen": "2024-07-20T09:15:30Z"
    }
  ],
  "timeline": [
    {
      "timestamp": "2024-07-20T09:15:25Z",
      "event": "DNS resolution for malicious-c2.com",
      "severity": "medium",
      "category": "reconnaissance"
    },
    {
      "timestamp": "2024-07-20T09:15:30Z", 
      "event": "Initial C2 connection established",
      "severity": "high",
      "category": "command_control"
    },
    {
      "timestamp": "2024-07-20T09:20:15Z",
      "event": "Malware payload downloaded",
      "severity": "critical", 
      "category": "malware_delivery"
    },
    {
      "timestamp": "2024-07-20T09:25:45Z",
      "event": "Internal network scan detected",
      "severity": "medium",
      "category": "discovery"
    }
  ],
  "recommendations": [
    {
      "priority": "critical",
      "action": "block_c2_infrastructure", 
      "targets": ["185.220.101.45", "malicious-c2.com"],
      "rationale": "Active C2 communication detected"
    },
    {
      "priority": "high",
      "action": "isolate_infected_host",
      "target": "192.168.1.100",
      "rationale": "Host showing signs of compromise with malware download and C2 beaconing"
    },
    {
      "priority": "medium",
      "action": "monitor_lateral_movement",
      "targets": ["192.168.1.101", "192.168.1.102", "192.168.1.103"],
      "rationale": "Potential lateral movement targets identified"
    }
  ]
}

export const sampleProcmonData = {
  "metadata": {
    "collection_start": "2024-07-20T10:30:00Z",
    "collection_end": "2024-07-20T11:30:00Z",
    "host_info": {
      "hostname": "WORKSTATION-01",
      "os_version": "Windows 11 22H2",
      "architecture": "x64"
    },
    "parser_version": "2.1.0",
    "config_applied": {
      "filters": ["exclude_system_processes", "include_network_events"],
      "enrichment": ["process_ancestry", "file_reputation", "network_geolocation"],
      "aggregation_window": "1m"
    },
    "total_events": 15847,
    "event_types": {
      "process": 234,
      "file": 12456,
      "registry": 2891,
      "network": 266
    }
  },
  "events": [
    {
      "id": "evt_001234567890",
      "timestamp": "2024-07-20T10:30:15.123Z",
      "event_type": "process",
      "operation": "process_start",
      "result": "success",
      "process_info": {
        "pid": 4892,
        "ppid": 1234,
        "name": "suspicious_app.exe",
        "path": "C:\\Temp\\suspicious_app.exe",
        "command_line": "suspicious_app.exe --silent --config c:\\temp\\config.dat",
        "user": "DOMAIN\\user1",
        "session_id": 1,
        "integrity_level": "medium",
        "process_ancestry": [
          {"pid": 1234, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
          {"pid": 812, "name": "winlogon.exe", "path": "C:\\Windows\\System32\\winlogon.exe"}
        ]
      },
      "file_info": {
        "path": "C:\\Temp\\suspicious_app.exe",
        "size": 2048576,
        "hash": {
          "md5": "5d41402abc4b2a76b9719d911017c592",
          "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
          "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        },
        "attributes": ["hidden", "system"],
        "creation_time": "2024-07-20T10:29:45.456Z",
        "reputation": {
          "score": 15,
          "verdict": "malicious",
          "sources": ["virustotal", "hybrid_analysis"]
        }
      },
      "network_info": {
        "protocol": "tcp",
        "local_address": "192.168.1.100",
        "local_port": 49152,
        "remote_address": "185.220.101.45",
        "remote_port": 443,
        "direction": "outbound",
        "bytes_sent": 1024,
        "bytes_received": 2048,
        "geolocation": {
          "country": "RU",
          "asn": "AS12345",
          "organization": "Suspicious Hosting Ltd"
        }
      },
      "registry_info": {
        "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "Persistence",
        "value_data": "C:\\Temp\\suspicious_app.exe --autostart",
        "value_type": "REG_SZ"
      },
      "enrichment": {
        "threat_intel": {
          "iocs": ["hash_match", "c2_communication"],
          "mitre_tactics": ["T1055", "T1071"],
          "severity": "high"
        },
        "behavioral_analysis": {
          "anomaly_score": 8.5,
          "pattern_matches": ["credential_dumping", "lateral_movement"],
          "baseline_deviation": true
        },
        "context": {
          "first_seen": "2024-07-20T10:30:15.123Z",
          "frequency": 1,
          "related_events": ["evt_001234567891", "evt_001234567892"]
        }
      },
      "tags": ["malware", "persistence", "c2_communication", "high_priority"]
    },
    {
      "id": "evt_001234567891",
      "timestamp": "2024-07-20T10:30:16.789Z",
      "event_type": "file",
      "operation": "file_write",
      "result": "success",
      "process_info": {
        "pid": 4892,
        "name": "suspicious_app.exe",
        "path": "C:\\Temp\\suspicious_app.exe",
        "user": "DOMAIN\\user1"
      },
      "file_info": {
        "path": "C:\\Users\\user1\\AppData\\Roaming\\config.dat",
        "size": 4096,
        "hash": {
          "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        "attributes": ["hidden"],
        "creation_time": "2024-07-20T10:30:16.789Z"
      },
      "enrichment": {
        "threat_intel": {
          "mitre_tactics": ["T1059"],
          "severity": "medium"
        },
        "behavioral_analysis": {
          "anomaly_score": 6.2,
          "pattern_matches": ["config_file_drop"]
        }
      },
      "tags": ["file_drop", "configuration", "medium_priority"]
    }
  ],
  "process_tree": {
    "root_processes": [
      {
        "pid": 812,
        "name": "winlogon.exe",
        "start_time": "2024-07-20T10:00:00.000Z",
        "end_time": null,
        "children": [
          {
            "pid": 1234,
            "name": "explorer.exe",
            "start_time": "2024-07-20T10:05:00.000Z",
            "end_time": null,
            "children": [
              {
                "pid": 4892,
                "name": "suspicious_app.exe",
                "start_time": "2024-07-20T10:30:15.123Z",
                "end_time": "2024-07-20T10:35:30.456Z",
                "command_line": "suspicious_app.exe --silent --config c:\\temp\\config.dat",
                "user": "DOMAIN\\user1",
                "exit_code": 0,
                "children": [
                  {
                    "pid": 5124,
                    "name": "cmd.exe",
                    "start_time": "2024-07-20T10:32:00.789Z",
                    "end_time": "2024-07-20T10:32:05.123Z",
                    "command_line": "cmd.exe /c whoami",
                    "children": []
                  }
                ]
              }
            ]
          }
        ]
      }
    ],
    "orphaned_processes": [
      {
        "pid": 9876,
        "name": "unknown_parent.exe",
        "start_time": "2024-07-20T10:25:00.000Z",
        "reason": "parent_not_captured",
        "inferred_ppid": 1234
      }
    ],
    "pid_reuse_detected": [
      {
        "pid": 2048,
        "instances": [
          {"name": "notepad.exe", "start": "2024-07-20T10:20:00.000Z", "end": "2024-07-20T10:25:00.000Z"},
          {"name": "calc.exe", "start": "2024-07-20T10:30:00.000Z", "end": null}
        ]
      }
    ]
  },
  "aggregations": {
    "process_summary": [
      {
        "process_name": "suspicious_app.exe",
        "event_count": 47,
        "first_seen": "2024-07-20T10:30:15.123Z",
        "last_seen": "2024-07-20T10:35:22.456Z",
        "operations": {
          "process_start": 1,
          "file_write": 12,
          "registry_modify": 8,
          "network_connect": 26
        },
        "risk_score": 9.2
      }
    ],
    "network_summary": [
      {
        "remote_address": "185.220.101.45",
        "connection_count": 26,
        "total_bytes": 52480,
        "first_connection": "2024-07-20T10:30:20.123Z",
        "last_connection": "2024-07-20T10:35:15.789Z",
        "threat_intel": {
          "verdict": "malicious",
          "category": "c2_server"
        }
      }
    ],
    "file_summary": [
      {
        "file_path": "C:\\Temp\\suspicious_app.exe",
        "operations": ["create", "read", "execute"],
        "processes": ["suspicious_app.exe"],
        "risk_score": 8.8,
        "reputation": "malicious"
      }
    ]
  },
  "alerts": [
    {
      "id": "alert_001",
      "timestamp": "2024-07-20T10:30:25.000Z",
      "severity": "high",
      "title": "Potential Malware Execution Detected",
      "description": "Suspicious process suspicious_app.exe executed with C2 communication patterns",
      "related_events": ["evt_001234567890", "evt_001234567891"],
      "mitre_tactics": ["T1055", "T1071"],
      "recommended_actions": ["isolate_host", "collect_memory_dump", "block_c2_traffic"]
    }
  ]
}

export const threatLevelColors = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
  informational: 'bg-blue-500'
};

export const formatTimestamp = (timestamp) => {
  return new Date(timestamp).toLocaleString();
};

// Sample Combined Analysis Data based on report_combiner_schema.json
export const sampleCombinedData = {
  "meta": {
    "combined_at": "2024-12-08T14:30:45.123456Z",
    "sources": {
      "procmon": "/analysis/procmon_20241208.json",
      "memory": "/analysis/memory_dump_20241208.json",
      "network": "/analysis/network_capture_20241208.json"
    },
    "individual_risk_scores": {
      "procmon": 7.5,
      "memory": 8.2,
      "network": 6.1
    },
    "available_reports": ["procmon", "memory", "network"]
  },
  "procmon": null,
  "memory": null,
  "network": null,
  "summary": {
    "correlations": [
      {
        "type": "Process Correlation",
        "pid": "1234",
        "name": "malicious.exe",
        "path": "C:\\temp\\malicious.exe",
        "has_memory_artifacts": true,
        "has_network_artifacts": true,
        "description": "Process malicious.exe (PID 1234) observed across multiple data sources",
        "details": [
          "Process found in memory dump: malicious.exe",
          "Process made 15 network connections"
        ],
        "sources": ["procmon", "memory", "network"],
        "evidence_count": 18,
        "network_indicators": {
          "suspicious_ips": ["192.168.1.100", "203.0.113.45"],
          "suspicious_domains": ["malicious-domain.com"]
        }
      },
      {
        "type": "File Hash Correlation",
        "hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "path": "C:\\temp\\suspicious.dll",
        "description": "File C:\\temp\\suspicious.dll found in both Procmon events and memory",
        "details": ["File was accessed in Procmon and loaded in memory"],
        "sources": ["procmon", "memory"],
        "evidence_count": 5,
        "has_memory_artifacts": true,
        "has_network_artifacts": false
      },
      {
        "type": "MITRE Technique Correlation",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "sources": ["procmon", "memory"],
        "description": "MITRE technique T1055 observed in 2 different data sources",
        "details": ["Technique seen in: procmon, memory"],
        "evidence_count": 3
      },
      {
        "type": "Network IOC Correlation",
        "description": "Malicious domain communications detected across network traffic",
        "details": [
          "DNS queries to malicious-domain.com",
          "HTTP POST requests to exfiltration endpoint",
          "Suspicious user agent strings detected"
        ],
        "sources": ["network", "procmon"],
        "evidence_count": 12,
        "network_indicators": {
          "suspicious_ips": ["192.168.1.100"],
          "suspicious_domains": ["malicious-domain.com", "suspicious-site.net"]
        }
      }
    ],
    "iocs": {
      "ips": ["192.168.1.100", "10.0.0.50", "203.0.113.45", "198.51.100.25", "172.16.0.10"],
      "domains": ["malicious-domain.com", "suspicious-site.net", "evil-c2.org", "backdoor-server.net"],
      "urls": [
        "http://malicious-domain.com/payload.exe",
        "https://suspicious-site.net/config.php",
        "http://evil-c2.org/upload",
        "https://backdoor-server.net/beacon"
      ],
      "hashes_sha256": [
        "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456a1",
        "c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456a1b2"
      ],
      "hashes_md5": [
        "d41d8cd98f00b204e9800998ecf8427e",
        "098f6bcd4621d373cade4e832627b4f6",
        "5d41402abc4b2a76b9719d911017c592"
      ],
      "paths": [
        "C:\\temp\\malicious.exe",
        "C:\\Users\\user\\AppData\\Local\\suspicious.dll",
        "C:\\Windows\\System32\\drivers\\rootkit.sys",
        "C:\\ProgramData\\backdoor\\config.dat",
        "C:\\temp\\payload.bin"
      ],
      "registry_keys": [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Backdoor",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilService"
      ],
      "mutexes": ["Global\\MalwareMutex", "Local\\BackdoorSync", "Global\\TrojanLock"],
      "file_names": ["malicious.exe", "suspicious.dll", "rootkit.sys", "backdoor.exe", "payload.bin"],
      "process_names": ["malicious.exe", "backdoor.exe", "trojan.exe", "evil-service.exe"]
    },
    "timeline": {
      "events": [
        {
          "timestamp": "2024-12-08T14:15:30.123Z",
          "source": "procmon",
          "event_type": "process_create",
          "event": "Process Create: malicious.exe",
          "severity": "high",
          "description": "CreateFile operation on C:\\temp\\malicious.exe",
          "details": "Process creation with suspicious characteristics",
          "process_name": "malicious.exe",
          "pid": "1234"
        },
        {
          "timestamp": "2024-12-08T14:16:15.456Z",
          "source": "volatility",
          "event_type": "process_analysis",
          "event": "Process: malicious.exe (PID: 1234)",
          "severity": "high",
          "description": "Command: C:\\temp\\malicious.exe -silent -persist",
          "details": "Suspicious command line arguments detected",
          "process_name": "malicious.exe",
          "pid": "1234"
        },
        {
          "timestamp": "2024-12-08T14:17:22.789Z",
          "source": "pcap",
          "event_type": "dns_query",
          "event": "DNS Query: malicious-domain.com",
          "severity": "high",
          "description": "Response: 192.168.1.100",
          "details": "Query to known malicious domain"
        },
        {
          "timestamp": "2024-12-08T14:18:45.012Z",
          "source": "pcap",
          "event_type": "http_post",
          "event": "HTTP POST: malicious-domain.com/exfil",
          "severity": "critical",
          "description": "Status: 200, User-Agent: Mozilla/5.0 (compatible; Malware/1.0)",
          "details": "Data exfiltration attempt detected"
        },
        {
          "timestamp": "2024-12-08T14:19:10.345Z",
          "source": "procmon",
          "event_type": "registry_write",
          "event": "Registry Write: Run Key",
          "severity": "medium",
          "description": "Persistence mechanism established",
          "details": "Added malware to startup registry key"
        }
      ],
      "duration": "3m 40s",
      "first_event": "2024-12-08T14:15:30.123Z",
      "last_event": "2024-12-08T14:19:10.345Z"
    },
    "mitre_techniques": [
      {
        "technique_id": "T1055",
        "name": "Process Injection",
        "description": "Adversaries may inject code into processes to evade process-based defenses",
        "tactic": "defense-evasion",
        "sources": ["procmon", "memory"],
        "severity": "high",
        "confidence": "high",
        "evidence": [
          "Suspicious process hollowing detected in memory analysis",
          "DLL injection activities observed in Procmon logs"
        ]
      },
      {
        "technique_id": "T1547.001",
        "name": "Registry Run Keys / Startup Folder",
        "description": "Adversaries may achieve persistence by adding a program to a startup folder",
        "tactic": "persistence",
        "sources": ["procmon"],
        "severity": "medium",
        "confidence": "medium",
        "evidence": [
          "Registry modification to Run key detected"
        ]
      },
      {
        "technique_id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel",
        "tactic": "exfiltration",
        "sources": ["network"],
        "severity": "critical",
        "confidence": "high",
        "evidence": [
          "HTTP POST requests to known C2 infrastructure",
          "Large data transfers to external domains"
        ]
      },
      {
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "description": "Adversaries may communicate using application layer protocols to avoid detection",
        "tactic": "command-and-control",
        "sources": ["network"],
        "severity": "high",
        "confidence": "high",
        "evidence": [
          "HTTP communications with suspicious user agents",
          "Regular beacon traffic patterns detected"
        ]
      }
    ],
    "tags": [
      "alert_high",
      "ioc_domain",
      "ioc_ip_address",
      "malware",
      "memory_analysis",
      "network_analysis",
      "persistence",
      "procmon_analysis",
      "suspicious_activity",
      "threat_critical",
      "process_injection",
      "data_exfiltration",
      "c2_communication"
    ],
    "risk_score": 8.7,
    "risk_level": "High"
  },
  "analysis": {
    "correlations": {
      "process_memory": [
        {
          "type": "Process Match",
          "process_name": "malicious.exe",
          "pid": "1234",
          "procmon_events": 45,
          "memory_artifacts": 8,
          "correlation_strength": "high"
        }
      ],
      "network_process": [
        {
          "type": "Network Activity",
          "process_name": "malicious.exe",
          "connections": 15,
          "domains_contacted": 3,
          "correlation_strength": "high"
        }
      ],
      "cross_source": [
        {
          "type": "File Hash Match",
          "hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
          "sources": ["procmon", "memory"],
          "occurrences": 7
        }
      ]
    },
    "threat_landscape": {
      "threats": [
        {
          "name": "Advanced Persistent Threat Activity",
          "category": "apt",
          "severity": "critical",
          "description": "Sophisticated multi-stage attack with persistence mechanisms",
          "origin_country": "Unknown",
          "confidence": 85
        },
        {
          "name": "Data Exfiltration Campaign",
          "category": "malware",
          "severity": "high",
          "description": "Active data theft operation targeting sensitive information",
          "origin_country": "Unknown",
          "confidence": 78
        }
      ],
      "geolocation": {
        "suspicious_countries": ["Unknown", "Romania", "Russia"],
        "ip_geolocation": {
          "192.168.1.100": "Romania",
          "203.0.113.45": "Russia"
        }
      },
      "threat_actors": [
        {
          "name": "APT-Simulator",
          "type": "Advanced Persistent Threat",
          "confidence": 65,
          "origin": "Unknown",
          "motivation": "Cyber espionage"
        }
      ],
      "malware_families": [
        {
          "name": "GenericTrojan",
          "type": "Trojan",
          "severity": "high",
          "platform": "Windows",
          "first_seen": "2024-12-01T00:00:00Z"
        }
      ],
      "attack_vectors": [
        {
          "name": "Process Injection",
          "prevalence": 85,
          "effectiveness": 75,
          "detection_difficulty": 65
        },
        {
          "name": "Registry Persistence",
          "prevalence": 70,
          "effectiveness": 60,
          "detection_difficulty": 40
        }
      ]
    },
    "attack_timeline": {
      "total_duration": "3m 40s",
      "start_time": "2024-12-08T14:15:30.123Z",
      "end_time": "2024-12-08T14:19:10.345Z",
      "phases": [
        {
          "name": "initial-access",
          "start_time": "2024-12-08T14:15:30.123Z",
          "end_time": "2024-12-08T14:16:00.000Z",
          "description": "Initial malware execution and process creation",
          "events": [
            {
              "id": "evt_001",
              "timestamp": "2024-12-08T14:15:30.123Z",
              "event_type": "process_create",
              "severity": "high",
              "description": "malicious.exe process created",
              "source": "procmon"
            }
          ]
        },
        {
          "name": "execution",
          "start_time": "2024-12-08T14:16:00.000Z",
          "end_time": "2024-12-08T14:17:00.000Z",
          "description": "Malware execution and memory injection",
          "events": [
            {
              "id": "evt_002",
              "timestamp": "2024-12-08T14:16:15.456Z",
              "event_type": "process_analysis",
              "severity": "high",
              "description": "Process injection techniques detected",
              "source": "memory"
            }
          ]
        },
        {
          "name": "command-and-control",
          "start_time": "2024-12-08T14:17:00.000Z",
          "end_time": "2024-12-08T14:18:30.000Z",
          "description": "Establishment of C2 communications",
          "events": [
            {
              "id": "evt_003",
              "timestamp": "2024-12-08T14:17:22.789Z",
              "event_type": "dns_query",
              "severity": "high",
              "description": "DNS resolution of malicious domain",
              "source": "network"
            }
          ]
        },
        {
          "name": "exfiltration",
          "start_time": "2024-12-08T14:18:30.000Z",
          "end_time": "2024-12-08T14:19:10.345Z",
          "description": "Data exfiltration activities",
          "events": [
            {
              "id": "evt_004",
              "timestamp": "2024-12-08T14:18:45.012Z",
              "event_type": "http_post",
              "severity": "critical",
              "description": "Data exfiltration via HTTP POST",
              "source": "network"
            }
          ]
        }
      ],
      "events": [
        {
          "timestamp": "2024-12-08T14:15:30.123Z",
          "event_type": "process_create",
          "severity": "high",
          "description": "malicious.exe process created",
          "source": "procmon"
        },
        {
          "timestamp": "2024-12-08T14:16:15.456Z",
          "event_type": "process_analysis",
          "severity": "high",
          "description": "Process injection techniques detected",
          "source": "memory"
        },
        {
          "timestamp": "2024-12-08T14:17:22.789Z",
          "event_type": "dns_query",
          "severity": "high",
          "description": "DNS resolution of malicious domain",
          "source": "network"
        },
        {
          "timestamp": "2024-12-08T14:18:45.012Z",
          "event_type": "http_post",
          "severity": "critical",
          "description": "Data exfiltration via HTTP POST",
          "source": "network"
        }
      ],
      "kill_chain": [
        {
          "phase": "initial-access",
          "description": "Malware gains initial foothold on the system",
          "start_time": "2024-12-08T14:15:30.123Z",
          "end_time": "2024-12-08T14:16:00.000Z"
        },
        {
          "phase": "execution",
          "description": "Malware executes and injects into processes",
          "start_time": "2024-12-08T14:16:00.000Z",
          "end_time": "2024-12-08T14:17:00.000Z"
        },
        {
          "phase": "command-and-control",
          "description": "Establishes communication with C2 infrastructure",
          "start_time": "2024-12-08T14:17:00.000Z",
          "end_time": "2024-12-08T14:18:30.000Z"
        },
        {
          "phase": "exfiltration",
          "description": "Exfiltrates sensitive data",
          "start_time": "2024-12-08T14:18:30.000Z",
          "end_time": "2024-12-08T14:19:10.345Z"
        }
      ]
    },
    "evidence_summary": {
      "artifacts": [
        {
          "type": "file",
          "name": "malicious.exe",
          "path": "C:\\temp\\malicious.exe",
          "size": 2048576,
          "hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
          "source": "procmon",
          "severity": "critical",
          "created_time": "2024-12-08T14:15:30.123Z",
          "description": "Primary malware executable",
          "analysis_notes": "Packed executable with anti-analysis techniques"
        },
        {
          "type": "memory",
          "name": "Process Injection Artifact",
          "path": "Memory Region 0x7FF000000000",
          "size": 65536,
          "source": "volatility",
          "severity": "high",
          "description": "Injected code detected in legitimate process",
          "analysis_notes": "Classic process hollowing technique"
        },
        {
          "type": "network",
          "name": "C2 Communication",
          "path": "HTTP Session to malicious-domain.com",
          "source": "pcap",
          "severity": "critical",
          "description": "Command and control traffic",
          "analysis_notes": "Regular beacon pattern every 60 seconds"
        },
        {
          "type": "registry",
          "name": "Persistence Registry Key",
          "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
          "source": "procmon",
          "severity": "medium",
          "description": "Registry key for persistence",
          "analysis_notes": "Standard persistence mechanism"
        }
      ],
      "evidence_chain": [
        {
          "action": "Evidence Collection",
          "timestamp": "2024-12-08T14:30:00.000Z",
          "analyst": "Automated Analysis System",
          "description": "Initial evidence collection from multiple sources"
        },
        {
          "action": "Cross-Correlation Analysis",
          "timestamp": "2024-12-08T14:30:15.000Z",
          "analyst": "Correlation Engine",
          "description": "Identified relationships between artifacts across data sources"
        },
        {
          "action": "IOC Extraction",
          "timestamp": "2024-12-08T14:30:30.000Z",
          "analyst": "IOC Extractor",
          "description": "Extracted indicators of compromise from all sources"
        },
        {
          "action": "Risk Assessment",
          "timestamp": "2024-12-08T14:30:45.000Z",
          "analyst": "Risk Calculator",
          "description": "Calculated overall risk score and threat level"
        }
      ],
      "forensic_notes": [
        {
          "title": "Malware Analysis Summary",
          "content": "The malicious.exe appears to be a sophisticated piece of malware utilizing process injection techniques to evade detection. It establishes persistence through registry modifications and communicates with C2 infrastructure for command execution and data exfiltration.",
          "analyst": "Security Analyst",
          "timestamp": "2024-12-08T15:00:00.000Z"
        },
        {
          "title": "Network Behavior Analysis",
          "content": "Network analysis reveals regular beacon traffic to known malicious domains. The communication pattern suggests an active C2 channel with periodic check-ins and data exfiltration activities.",
          "analyst": "Network Analyst",
          "timestamp": "2024-12-08T15:15:00.000Z"
        }
      ],
      "recommendations": [
        {
          "title": "Immediate Containment",
          "description": "Isolate affected systems and block communication to identified malicious domains",
          "priority": "high"
        },
        {
          "title": "IOC Deployment",
          "description": "Deploy all identified IOCs to security tools for detection and prevention",
          "priority": "high"
        },
        {
          "title": "Registry Cleanup",
          "description": "Remove persistence mechanisms from registry keys",
          "priority": "medium"
        },
        {
          "title": "Enhanced Monitoring",
          "description": "Implement enhanced monitoring for similar attack patterns",
          "priority": "medium"
        }
      ]
    }
  }
};
