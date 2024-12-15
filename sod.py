from tinyec.ec import SubGroup, Curve
import time
from tqdm import tqdm  # For progress bar

# Function to check if a point lies on the elliptic curve
def is_on_curve(X, Y, curve):
    """Validate if a point is on the elliptic curve."""
    lhs = (Y * Y) % curve.field.p
    rhs = (X * X * X + curve.a * X + curve.b) % curve.field.p
    return lhs == rhs

# Function to validate public key
def validate_public_key(X, Y, curve):
    """Validate the public key coordinates."""
    if not is_on_curve(X, Y, curve):
        print("[!] Invalid public key. It does not lie on the curve.")
        return False
    return True

# Function to handle compressed public key
def decompress_public_key(compressed_key, curve):
    """Decompress a compressed public key."""
    prefix = compressed_key[:2]
    X = int(compressed_key[2:], 16)
    p = curve.field.p

    # Calculate Y^2 = X^3 + 7 (mod p)
    y_squared = (X * X * X + curve.a * X + curve.b) % p
    Y = pow(y_squared, (p + 1) // 4, p)

    # Use the prefix to determine which Y coordinate to use
    if prefix == "02" and Y % 2 != 0:
        Y = p - Y
    elif prefix == "03" and Y % 2 == 0:
        Y = p - Y

    return X, Y

# Function to recover private key using brute force with a progress bar
def recover_private_key(public_key, curve, max_keys=2**20):
    """Brute-force recovery of private key using known public key."""
    print("[*] Starting brute force...")
    for k in tqdm(range(1, max_keys), desc="Searching...", unit="Comparisons"):
        candidate_point = k * curve.g
        if candidate_point == public_key:
            return k
    return None

# Function to save the recovered key to a file
def save_to_file(filename, private_key):
    """Save the recovered private key to a file."""
    with open(filename, "w") as file:
        file.write(f"Recovered Private Key: {hex(private_key)}\n")
    print(f"[+] Private key saved to {filename}")

# Main function
def main():
    # secp256k1 curve parameters
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0x0
    b = 0x7
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    h = 1

    curve = Curve(a, b, SubGroup(p, (Gx, Gy), n, h), name="secp256k1")

    print("[*] Enter the public key (compressed or uncompressed format):")
    public_key_input = input("Public Key: ").strip()

    # Process public key input
    if public_key_input.startswith("04"):  # Uncompressed public key
        X = int(public_key_input[2:66], 16)
        Y = int(public_key_input[66:], 16)
    elif public_key_input.startswith("02") or public_key_input.startswith("03"):  # Compressed public key
        X, Y = decompress_public_key(public_key_input, curve)
    else:
        print("[!] Invalid public key format.")
        return

    # Validate the public key
    if not validate_public_key(X, Y, curve):
        return

    # Create the public key point
    public_key = curve.field.g * 1
    print("[*] Public key validated. Starting recovery process...")

    # Attempt to recover the private key
    private_key = recover_private_key(public_key, curve, max_keys=2**20)
    if private_key:
        print(f"[+] Private key found: {hex(private_key)}")
        save_to_file("found.txt", private_key)
    else:
        print("[!] Failed to recover private key.")

if __name__ == "__main__":
    main()
