import ipaddress
import socket
from typing import List, Set

def parse_targets(target_spec: str, visited_files=None) -> List[str]:
    """Convert target specification into individual IP addresses"""
    if visited_files is None:
        visited_files = set()

    # Handle file input
    if target_spec.startswith('@'):
        file_path = target_spec[1:]
        return _read_targets_from_file(file_path, visited_files)

    # Handle comma-separated lists
    if ',' in target_spec:
        targets = []
        for part in target_spec.split(','):
            if part.strip():  # Skip empty parts
                targets.extend(parse_targets(part.strip(), visited_files))
        return targets

    # Handle IP ranges
    if '-' in target_spec:
        return _expand_ip_range(target_spec)

    # Handle CIDR notation
    if '/' in target_spec:
        return _expand_cidr(target_spec)

    # Handle single IPs and hostnames
    if _is_ip(target_spec):
        return [target_spec]
    else:
        return _resolve_hostname(target_spec)

def _is_ip(target: str) -> bool:
    """Check if target is an IPv4/IPv6 address"""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def _resolve_hostname(hostname: str) -> List[str]:
    """Resolve hostname to IP addresses (IPv4 and IPv6)"""
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
        # Use set to deduplicate addresses
        return list({addr[4][0] for addr in addrinfo})
    except socket.gaierror:
        return []  # Return empty list if resolution fails

def _expand_ip_range(range_spec: str) -> List[str]:
    """Expand any valid IP range format to individual IPs"""
    if '-' not in range_spec:
        return [range_spec]

    # Handle IPv6 ranges
    if ':' in range_spec:
        return _expand_ipv6_range(range_spec)
    
    # Handle IPv4 ranges
    return _expand_ipv4_range(range_spec)

def _expand_ipv6_range(range_spec: str) -> List[str]:
    """Expand IPv6 range formats with support for partial numeric ranges"""
    parts = range_spec.split('-')
    if len(parts) != 2:
        return []
    
    start_str, end_str = [part.strip() for part in parts]
    
    try:
        # Parse start address
        start_ip = ipaddress.IPv6Address(start_str)
        start_int = int(start_ip)
        
        # Try to parse end as full IPv6 address first
        try:
            end_ip = ipaddress.IPv6Address(end_str)
            end_int = int(end_ip)
        except ValueError:
            # If not a full address, treat as the final value for the last hextet
            try:
                # Get the exploded form of start address
                hextets = start_ip.exploded.split(':')
                
                # Parse end value (could be decimal or hex)
                if end_str.lower().startswith('0x'):
                    end_val = int(end_str[2:], 16)
                else:
                    end_val = int(end_str)
                
                # Replace last hextet with end value
                hextets[-1] = '{:04x}'.format(end_val)
                end_ip = ipaddress.IPv6Address(':'.join(hextets))
                end_int = int(end_ip)
            except ValueError:
                return []
        
        # Validate range
        if start_int > end_int:
            return []
        
        # Generate IPs
        ips = []
        for ip_int in range(start_int, end_int + 1):
            ips.append(str(ipaddress.IPv6Address(ip_int)))
        return ips
        
    except (ValueError, ipaddress.AddressValueError):
        return []

def _expand_ipv4_range(range_spec: str) -> List[str]:
    try:
        base_part, end_part = range_spec.rsplit('-', 1)
        
        # Parse start IP
        start_ip = ipaddress.IPv4Address(base_part)
        start_octets = base_part.split('.')
        
        # Split end part and get number of octets
        end_octets = end_part.split('.')
        
        # Construct full end IP by combining start octets and end octets
        if len(end_octets) < 4:
            # Take necessary octets from start IP
            num_octets_from_start = 4 - len(end_octets)
            full_end = '.'.join(start_octets[:num_octets_from_start] + end_octets)
        else:
            full_end = end_part
        
        # Parse end IP
        end_ip = ipaddress.IPv4Address(full_end)
        
        # Generate IPs
        if start_ip > end_ip:
            return []
        
        return [
            str(ipaddress.IPv4Address(ip_int))
            for ip_int in range(int(start_ip), int(end_ip) + 1)
        ]
    except (ValueError, ipaddress.AddressValueError):
        return []

def _expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to individual IPs"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []

def _read_targets_from_file(file_path: str, visited_files: Set[str]) -> List[str]:
    """Read targets from file, one per line, and parse each line"""
    try:
        # Prevent circular references
        if file_path in visited_files:
            return []
        visited_files.add(file_path)

        targets = []
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    targets.extend(parse_targets(line, visited_files))
        return targets
    except FileNotFoundError:
        print(f"[x] Warning: File not found - {file_path}")
        return []
    except Exception as error:
        print(f"[x] Warning: Error reading file - {error}")
        return []


#if __name__ == "__main__":
    # Test cases
    ##### IPv4 tests [successful]
    #print(parse_targets("192.168.1.1"))  # Single IP
    #print(parse_targets("192.168.1.1-192.168.1.10"))  # Simple IPv4 range
    #print(parse_targets("192.168.1.200-192.168.2.50"))  # Cross-octet IPv4 range
    #print(parse_targets("2001:db8::1-2001:db8::10"))  # Simple IPv6 range
    #print(parse_targets("192.168.1.0/24"))  # IPv4 CIDR
    #print(parse_targets("2001:db8::/123"))  # IPv6 CIDR
    #print(parse_targets("192.168.1.1,192.168.1.2,192.168.1.3"))  # Comma-separated IPs
    #print(parse_targets("192.168.1.250-255"))
    #print(parse_targets("192.168.1.250-240")) #should give no IP
    #print(parse_targets("192.168.255.250-169.0.10,192.255.255.255-193.0.0.10"))  # Comma-separated ranges
    ##### Local & Public Domains test [successful]
    #print(parse_targets("example.com,localhost,test.thm"))  # Hostname
    ##### IPv6 tests [successful except !!]
    #print(parse_targets("2001:0db8:0000:0000:0000:0000:0000:0001-3"))
    #print(parse_targets("2001:db8::1-5"))
    #!!#print(parse_targets("2001:db8:0:0:0:abcd::100-105"))
    #!!#print(parse_targets("2001:db8::fffe-10000"))
    #print(parse_targets("2001:0db8:0000:0000:0001::0001-0003"))
    #print(parse_targets("2001::db8::1-3"))  # Should return [] (invalid IPv6)
    #print(parse_targets("2001:DB8:aBcD::1-3"))
    #print(parse_targets("fe80::1%eth0-3"))  # Should return [] (interface IDs not supported)
    #print(parse_targets("::1-3"))
    #print(parse_targets("2001:db8::0-3"))
    ###### File test [successful]
    #print(parse_targets("@tests/hosts"))
