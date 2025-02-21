#!/usr/bin/env python

import argparse
import sys

from openapi_parser import parse  # pip install openapi3-parser
from openapi_parser.enumeration import DataType

DEFAULT_FILE = "https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/specificatie/resolved/openapi.yaml"


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Show the OpenAPI structure")
    parser.add_argument("filename", nargs="?", help="Location of the OpenAPI file")
    parser.add_argument("--format", default="tree", choices=["tree", "csv"], help="Output format")
    parser.add_argument(
        "--schema", default="RaadpleegMetBurgerservicenummerResponse", help="Component to print"
    )

    args = parser.parse_args()

    _print_openapi(args.filename or DEFAULT_FILE, schema=args.schema, format=args.format)


def _print_openapi(filename, schema, format):
    api = parse(filename, strict_enum=False)

    response_schema = api.schemas[schema]

    if format == "csv":
        print("pad\ttype")
    _print_object(response_schema.properties, format=format)


def _print_object(properties, prefix="", format="tree"):
    """Recursively print the structure of a schema"""
    is_csv = format == "csv"
    for field in properties:
        data_type = field.schema.type  # enum type
        sep = "\t" if is_csv else " "
        print(f"{prefix}{field.name}{sep}{data_type.value}")

        if data_type == DataType.OBJECT:
            _print_object(
                field.schema.properties,
                prefix=(f"{prefix}{field.name}." if is_csv else f"{prefix}  "),
                format=format,
            )
        elif data_type == DataType.ARRAY:
            if not is_csv:
                print(f"{prefix}  (array of)")
            _print_object(
                field.schema.items.properties,
                prefix=(f"{prefix}{field.name}[]." if is_csv else f"{prefix}  |  "),
                format=format,
            )


if __name__ == "__main__":
    main()
