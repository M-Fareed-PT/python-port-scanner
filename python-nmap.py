import nmap
import sys

def scan_target(target, ports='80,443', arguments='-sV -p'):
    nm = nmap.PortScanner()
    try:
        # Build arguments string
        args = f"-sV -p {ports}"
        nm.scan(hosts=target, arguments=args)
    except nmap.PortScannerError as e:
        print("nmap error:", e, file=sys.stderr)
        return
    except Exception as e:
        print("Unexpected error:", e, file=sys.stderr)
        return

    hosts = nm.all_hosts()
    if not hosts:
        print(f"No hosts found for target {target}. (Check connectivity, target format, firewall or nmap installation.)")
        return

    for host in hosts:
        hostname = nm[host].hostname() or '(no hostname)'
        state = nm[host].state() or '(unknown)'
        print(f"Host : {host} ({hostname})")
        print(f"State: {state}")

        # some hosts may not have protocols (if down or filtered)
        protocols = nm[host].all_protocols()
        if not protocols:
            print("  No protocols found (host may be down/filtered).")
            continue

        for proto in protocols:
            print(f"Protocol : {proto}")
            ports_dict = nm[host][proto]
            # iterate sorted ports for consistent output
            for port in sorted(ports_dict.keys()):
                info = ports_dict[port]
                port_state = info.get('state', '(unknown)')
                service = info.get('name', '')
                product = info.get('product', '')
                version = info.get('version', '')
                extrainfo = info.get('extrainfo', '')
                service_str = service
                if product or version:
                    service_str += f" ({product} {version})".strip()
                if extrainfo:
                    service_str += f" -- {extrainfo}"
                print(f"  port: {port}\tstate: {port_state}\tservice: {service_str}")
        print("-" * 60)


if __name__ == "__main__":
    target_ip = "45.33.32.156"
    scan_target(target_ip, ports='80,443')
