import ipaddress
import socket
from pathlib import PATH
from typing import List, Dict

def parse_targets(target_spec: str) -> List[str]:
    ################ helpers #####################
    def _is_ip(target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def _resolve_hostname(hostname: str) -> List[str]:
        """Resolve hostname to IP addresses"""
        try:
            # Get all IP addresses for the hostname
            addrinfo = socket.getaddrinfo(hostname, None)
            ips = list({addr[4][0] for addr in addrinfo})
            return ips
        except socket.gaierror:
            return []  # Return empty list if resolution fails
    def _expand_ip_range(range_spec: str) -> List[str]:
        """Expand any valid IP range format to individual IPs"""
        try:
            if '-' not in range_spec:
                return [range_spec]
            
            base_part, range_part = range_spec.rsplit('-', 1)
            
            # Handle cases where base_part might be incomplete (like "192.168-1.2")
            base_parts = base_part.split('.') if base_part else []
            range_parts = range_part.split('.')
            
            # Pad parts with None to make equal length
            max_length = max(len(base_parts), len(range_parts))
            base_parts += [None] * (max_length - len(base_parts))
            range_parts += [None] * (max_length - len(range_parts))
            
            # Build start and end IPs
            start_ip_parts = []
            end_ip_parts = []
            
            for base, range_val in zip(base_parts, range_parts):
                if base is not None and range_val is None:
                    # Case: "192.168.1.100-200" -> range_val is "200"
                    start_ip_parts.append(base)
                    end_ip_parts.append(base)
                elif base is None and range_val is not None:
                    # Case: "-200" or "-1.200"
                    start_ip_parts.append("0")
                    end_ip_parts.append(range_val)
                else:
                    # Case: "192.168.1.100-2.200"
                    start_ip_parts.append(base)
                    end_ip_parts.append(range_val)
            
            # Handle partial ranges
            for i in reversed(range(len(start_ip_parts))):
                if start_ip_parts[i] is None:
                    start_ip_parts[i] = "0"
                if end_ip_parts[i] is None:
                    end_ip_parts[i] = start_ip_parts[i]
            
            start_ip = '.'.join(start_ip_parts)
            end_ip = '.'.join(end_ip_parts)
            
            # Generate all IPs between start and end
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            if start > end:
                start, end = end, start  # Ensure start <= end
            
            return [str(ipaddress.IPv4Address(ip)) 
                    for ip in range(int(start), int(end) + 1)]
        
        except (ValueError, AttributeError):
            return []


    def _expand_cidr(cidr: str) -> List[str]:
        """Expand CIDR notation to individual IPs"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(host) for host in network.hosts()]
        except ValueError:
            return []


    def _read_targets_from_file(file_path: str) -> List[str]:
        """Read targets from file, one per line, and parse each line"""
        try:
            targets = []
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    #if line and not line.startswith('#'):  # Skip empty lines and comments
                    targets.extend(parse_targets(line))
            return targets
        except FileNotFoundError:
            print(f"[x] Warning: File not found - {file_path}")
            return []
        except Exception as error:
            print(f"[x] Warning: Error reading file - {error}")
            return []
    ######################################################################

    # Handle file input -p @port1
    if target_spec.startswith('@'):
        file_path = target_spec[1:]
        return _read_targets_from_file(file_path)
    # Handle comma-separated lists -p @port1.txt,1.1.1.1-1.4,80,33,1-10,8.8.8.8/24
    if ',' in target_spec:
        targets = []
        for part in target_spec.split(','):
            targets.extend(parse_targets(part.strip()))
        return targets
    
    # Handle IP ranges (e.g., 192.168.1.100-200)
    if '-' in target_spec:
        return _expand_ip_range(target_spec)
    
    # Handle CIDR notation
    if '/' in target_spec:
        return _expand_cidr(target_spec)
    
    if _is_ip(target_spec):
        # Handle Single IP
        return [target_spec]
    else:
        # Handle hostnames (localhost/domains)
        return _resolve_hostname(target_spec)
