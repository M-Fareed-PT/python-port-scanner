import nmap
import sys

def scan_target(target, ports='80,443'):
    nm = nmap.PortScanner()

    try:
        args = f"-sV -p {ports}"
        nm.scan(hosts=target, arguments=args)

    except nmap.PortScannerError as e:
        print("Nmap error:", e, file=sys.stderr)
        return

    except Exception as e:
        print("Unexpected error:", e, file=sys.stderr)
        return

    hosts = nm.all_hosts()
    if not hosts:
        print(f"\nNo hosts found for target {target}.")
        print("Check connectivity, target format, firewall or nmap installation.")
        return

    print("\n========== SCAN RESULTS ==========")

    for host in hosts:
        hostname = nm[host].hostname() or '(no hostname)'
        state = nm[host].state() or '(unknown)'

        print(f"\nHost   : {host} ({hostname})")
        print(f"State  : {state}")

        protocols = nm[host].all_protocols()
        if not protocols:
            print("No protocols found (host may be down or filtered).")
            continue

        for proto in protocols:
            print(f"\nProtocol : {proto}")
            ports_dict = nm[host][proto]

            for port in sorted(ports_dict.keys()):
                info = ports_dict[port]
                port_state = info.get('state', '(unknown)')
                service = info.get('name', '')
                product = info.get('product', '')
                version = info.get('version', '')
                extrainfo = info.get('extrainfo', '')

                service_str = service
                if product or version:
                    service_str += f" ({product} {version})"
                if extrainfo:
                    service_str += f" -- {extrainfo}"

                print(f"Port {port:<5} | {port_state:<6} | {service_str}")

    print("\n========== SCAN COMPLETED ==========")
    input("\nPress Enter to return to menu...")


def menu():
    print("\n====== PYTHON PORT SCANNER ======")
    print("1. Scan Target")
    print("2. Exit")
    print("================================")


def main():
    while True:
        menu()
        choice = input("Select option (1-2): ").strip()

        if choice == "1":
            target = input("\nEnter target IP or domain: ").strip()
            ports = input("Enter ports (e.g. 21,22,80,443): ").strip()

            if not target:
                print("\nTarget cannot be empty.")
                continue

            if not ports:
                ports = "80,443"

            scan_target(target, ports)

        elif choice == "2":
            print("\nExiting program...")
            break

        else:
            print("\nInvalid selection. Try again.")


if __name__ == "__main__":
    main()
