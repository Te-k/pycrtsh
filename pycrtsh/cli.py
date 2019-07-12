import argparse
import json
import datetime
from .api import Crtsh


def datetime_handler(x):
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    raise TypeError("Unknown type")


def main():
    parser = argparse.ArgumentParser(description='Request crt.sh')
    subparsers = parser.add_subparsers(help='Commands')
    parser_a = subparsers.add_parser('cert', help='Query an ')
    parser_a.add_argument('VALUE', help='Value to be requested, can be a crt.sh id, sha1, sha256 or serial')
    parser_a.set_defaults(which='cert')
    parser_b = subparsers.add_parser('domain', help='List certs related to a domain')
    parser_b.add_argument('DOMAIN', help='domain')
    parser_b.set_defaults(which='domain')
    args = parser.parse_args()

    if hasattr(args, 'which'):
        crt = Crtsh()
        if args.which == 'cert':
            types = {32: "serial", 40: "sha1", 64: "sha256"}
            try:
                t = types[len(args.VALUE)]
            except KeyError:
                t = "id"
            res = crt.get(args.VALUE, type=t)
            print(json.dumps(res, sort_keys=True, indent=4, default=datetime_handler))
        elif args.which == "domain":
            res = crt.search(args.DOMAIN)
            if len(res) == 0:
                print("No certificate found!")
            for r in res:
                if len(str(r["id"])) < 8:
                    print("%i\t\t%s\t%s\t%s" % (
                            r["id"],
                            r["logged_at"].isoformat(),
                            r["not_before"].isoformat(),
                            r["ca"]["name"]
                        )
                    )
                else:
                    print("%i\t%s\t%s\t%s" % (
                            r["id"],
                            r["logged_at"].isoformat(),
                            r["not_before"].isoformat(),
                            r["ca"]["name"]
                        )
                    )
        else:
            parser.print_help()
    else:
        parser.print_help()
