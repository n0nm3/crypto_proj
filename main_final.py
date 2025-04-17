import sys
from src.load import verify_certificate_chain

def main():
    if len(sys.argv) < 4 or sys.argv[1] != "-format" or sys.argv[2] not in ["PEM", "DER"]:
        print("Usage: python main.py -format <PEM|DER> <cert1> <cert2> ...")
        sys.exit(1)

    file_format = sys.argv[2]
    cert_files = sys.argv[3:]

    if verify_certificate_chain(file_format, cert_files):
        print("Chaîne de certificats valide :)")
    else:
        print("Chaîne de certificats invalide :(")

if __name__ == "__main__":
    main()