import argparse
import binascii

from kmip.core import enums
from kmip.pie.client import ProxyKmipClient


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()

    client = ProxyKmipClient(
        hostname=args.host,
        port=args.port,
        cert=args.cert,
        key=args.key,
        ca=args.ca,
        config=None,
    )
    with client:
        uid = client.create(enums.CryptographicAlgorithm.AES, 256)
        key = client.get(uid)
    if key.cryptographic_algorithm != enums.CryptographicAlgorithm.AES:
        raise SystemExit(f"unexpected algorithm: {key.cryptographic_algorithm}")
    if key.cryptographic_length != 256:
        raise SystemExit(f"unexpected key length: {key.cryptographic_length}")
    if len(key.value) != 32:
        raise SystemExit(f"unexpected value length: {len(key.value)}")
    print(f"PYKMIP_OK uid={uid} value={binascii.hexlify(key.value[:4]).decode()}...")


if __name__ == "__main__":
    main()
