import argparse

def main():
    parser = argparse.ArgumentParser(
        description = "DEMO argument parsing"
    )
    parser.add_argument(
        "-t", "--target",
        type = str,
        required = True,
        help = "Formats: single/multiple/range/CIDR/file\n"
                "Content: IPv4/IPv6/DomainName/HostName\n"
                "Separation: ',' for multiple, '-' for range, '/' for CIDR"
    )
    parser.add_argument(
        "-p", "--port",
        type = str,
        required = True,
        help = "Formats: single/multiple/range/file\n"
                "Content: number/'all'\n"
                "Separation: ',' for multiple, '-' for range"
    )
    parser.add_argument(
        "-v", "--verbose",
        action = "store_true",
        help = "output details & results "
    )
    parser.add_argument(
        "-q", "--quiet",
        action = "store_true",
        help = "output results only"
    )
    parser.add_argument(
        "-o", "--output",
        type = str,
        help = "Formats: single/multiple\n"
                "Content: filename\n"
                "Separation: ',' for multiple\n"
                "Filetypes: raw, csv, xml, json, md, db, yaml, nmap, gnmap"
    )

    args = parser.parse_args()

    if args.quiet and args.verbose:
        parser.error("-q/--quiet and -v/--verbose cannot be used together")



if __name__ == "__main__" :
    main()
