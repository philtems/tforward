TCP port forwarder with blacklist support

Usage: tforward [OPTIONS] --rule <RULE>

Options:

  -r, --rule <RULE>
          Forwarding rules in format "0.0.0.0:8080:192.168.1.10:80"
          
  -b, --blocklist <BLOCKLIST>
          File containing blacklist (IP or CIDR per line)
          
  --reload-interval <RELOAD_INTERVAL>
          Blacklist reload interval in seconds (default: 300) [default: 300]
          
  --log-level <LOG_LEVEL>
          Log level (info, debug, warn) [default: info]
      
  --daemonize
          Daemon mode: detach from terminal and run in background
      
  --pid-file <PID_FILE>
          PID file for daemon mode [default: /var/run/tforward.pid]
      
  --log-file <LOG_FILE>
          Log file for daemon mode (default: stdout redirected to /var/log/tforward.log) [default: /var/log/tforward.log]
  
  -h, --help
          Print help
  
  -V, --version
          Print version
