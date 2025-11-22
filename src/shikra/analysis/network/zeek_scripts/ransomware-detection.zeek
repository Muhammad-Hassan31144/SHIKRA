# Zeek script for detecting ransomware-related network activity
# This script identifies patterns commonly associated with ransomware operations

@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/files/extract

module RansomwareDetection;

export {
    ## Create a new log stream for ransomware indicators
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        uid: string &log &optional;
        id: conn_id &log &optional;
        indicator_type: string &log;
        indicator_value: string &log;
        confidence: string &log;
        description: string &log;
        source_ip: addr &log &optional;
        dest_ip: addr &log &optional;
        dest_port: port &log &optional;
    };
    
    ## Suspicious domain patterns commonly used by ransomware
    const suspicious_domains = {
        /.*\.onion$/,
        /.*\.bazar$/,
        /.*\.bit$/,
        /.*\.top$/,
        /.*\.xyz$/,
        /.*\.monster$/,
        /.*tor2web.*/,
        /.*\.ddns\.net$/,
        /.*\.no-ip\.com$/,
        /.*\.duckdns\.org$/,
        /.*\.hopto\.org$/,
        /.*\.zapto\.org$/
    };
    
    ## Ransomware-related keywords in HTTP traffic
    const ransomware_keywords = {
        /ransom/i,
        /decrypt/i,
        /bitcoin/i,
        /monero/i,
        /payment/i,
        /wallet/i,
        /crypto/i,
        /cipher/i,
        /encrypt/i,
        /locked/i,
        /restore/i,
        /recovery/i
    };
    
    ## Suspicious user agents often used by ransomware
    const suspicious_user_agents = {
        /^$/,  # Empty user agent
        /curl\/[0-9]/,
        /wget\/[0-9]/,
        /powershell/i,
        /python-requests/,
        /Go-http-client/,
        /Mozilla\/4\.0 \(compatible; MSIE 6\.0; Windows NT 5\.1\)/
    };
    
    ## C2 communication patterns
    const c2_patterns = {
        /\/[a-f0-9]{32,64}$/,  # Long hex strings in URIs
        /\/[A-Za-z0-9+\/]{20,}={0,2}$/,  # Base64-like patterns
        /\/(config|update|check|status|ping|beacon)$/i
    };
    
    ## Cryptocurrency wallet address patterns
    const crypto_addresses = {
        /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/,  # Bitcoin
        /^bc1[a-z0-9]{39,59}$/,               # Bitcoin Bech32
        /^0x[a-fA-F0-9]{40}$/,               # Ethereum
        /^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/ # Monero
    };
}

event zeek_init() {
    Log::create_stream(RansomwareDetection::LOG, [$columns=RansomwareDetection::Info, $path="ransomware"]);
}

function log_indicator(c: connection, indicator_type: string, value: string, confidence: string, description: string) {
    local info = RansomwareDetection::Info(
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id,
        $indicator_type = indicator_type,
        $indicator_value = value,
        $confidence = confidence,
        $description = description,
        $source_ip = c$id$orig_h,
        $dest_ip = c$id$resp_h,
        $dest_port = c$id$resp_p
    );
    Log::write(RansomwareDetection::LOG, info);
}

# DNS Analysis
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Check for suspicious domains
    for (pattern in suspicious_domains) {
        if (pattern in query) {
            log_indicator(c, "SUSPICIOUS_DOMAIN", query, "HIGH", 
                         fmt("DNS query to suspicious domain: %s", query));
        }
    }
    
    # Check for DNS tunneling (long domain names)
    if (|query| > 50) {
        log_indicator(c, "DNS_TUNNELING", query, "MEDIUM", 
                     fmt("Potentially tunneled DNS query: %s", query));
    }
    
    # Check for cryptocurrency addresses in DNS queries
    for (pattern in crypto_addresses) {
        if (pattern in query) {
            log_indicator(c, "CRYPTO_ADDRESS", query, "HIGH", 
                         fmt("Cryptocurrency address in DNS query: %s", query));
        }
    }
}

# HTTP Analysis
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    # Check for ransomware keywords in URI
    for (pattern in ransomware_keywords) {
        if (pattern in unescaped_URI) {
            log_indicator(c, "RANSOMWARE_KEYWORD", unescaped_URI, "MEDIUM", 
                         fmt("Ransomware keyword in HTTP URI: %s", unescaped_URI));
        }
    }
    
    # Check for C2 communication patterns
    for (pattern in c2_patterns) {
        if (pattern in unescaped_URI) {
            log_indicator(c, "C2_PATTERN", unescaped_URI, "HIGH", 
                         fmt("Potential C2 communication pattern: %s", unescaped_URI));
        }
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "USER-AGENT") {
        # Check for suspicious user agents
        for (pattern in suspicious_user_agents) {
            if (pattern in value) {
                log_indicator(c, "SUSPICIOUS_USER_AGENT", value, "MEDIUM", 
                             fmt("Suspicious user agent: %s", value));
            }
        }
    }
    
    # Check for cryptocurrency addresses in any header
    for (pattern in crypto_addresses) {
        if (pattern in value) {
            log_indicator(c, "CRYPTO_ADDRESS", value, "HIGH", 
                         fmt("Cryptocurrency address in HTTP header %s: %s", name, value));
        }
    }
}

# SSL/TLS Analysis
event ssl_established(c: connection) {
    if (c$ssl?$server_name) {
        # Check server name against suspicious domains
        for (pattern in suspicious_domains) {
            if (pattern in c$ssl$server_name) {
                log_indicator(c, "SUSPICIOUS_SSL_DOMAIN", c$ssl$server_name, "HIGH", 
                             fmt("SSL connection to suspicious domain: %s", c$ssl$server_name));
            }
        }
    }
}

# File Analysis
event file_new(f: fa_file) {
    # Track executable files
    if (f$info?$mime_type && /application\/x-dosexec/ in f$info$mime_type) {
        # This will be logged by the files.log, but we can add custom logic here
    }
}

# Connection Analysis for beaconing detection
global connection_intervals: table[addr, addr, port] of vector of interval;
global last_connection_time: table[addr, addr, port] of time;

event connection_established(c: connection) {
    local key = [c$id$orig_h, c$id$resp_h, c$id$resp_p];
    
    if (key in last_connection_time) {
        local interval_time = network_time() - last_connection_time[key];
        
        if (key !in connection_intervals) {
            connection_intervals[key] = vector();
        }
        
        connection_intervals[key][|connection_intervals[key]|] = interval_time;
        
        # Check for regular beaconing (simple heuristic)
        if (|connection_intervals[key]| >= 5) {
            local avg_interval = 0.0;
            for (i in connection_intervals[key]) {
                avg_interval += interval_to_double(connection_intervals[key][i]);
            }
            avg_interval = avg_interval / |connection_intervals[key]|;
            
            # Calculate variance to detect regular intervals
            local variance = 0.0;
            for (i in connection_intervals[key]) {
                local diff = interval_to_double(connection_intervals[key][i]) - avg_interval;
                variance += diff * diff;
            }
            variance = variance / |connection_intervals[key]|;
            
            # If variance is low, it might be beaconing
            if (variance < 1.0 && avg_interval > 10.0 && avg_interval < 3600.0) {
                log_indicator(c, "BEACONING_PATTERN", fmt("%.2f", avg_interval), "HIGH", 
                             fmt("Regular beaconing detected with %d second intervals", double_to_count(avg_interval)));
            }
        }
    }
    
    last_connection_time[key] = network_time();
}

# Data exfiltration detection
event connection_state_remove(c: connection) {
    if (c$conn?$orig_bytes && c$conn$orig_bytes > 10485760) {  # > 10MB upload
        log_indicator(c, "DATA_EXFILTRATION", fmt("%d", c$conn$orig_bytes), "MEDIUM", 
                     fmt("Large data upload detected: %d bytes", c$conn$orig_bytes));
    }
}
