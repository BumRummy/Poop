# -*- coding: utf-8 -*-
"""
Combined Script for Extracting Reused r Signatures and Attempting Private Key Recovery
@author: iceland
"""
import sys
import json
import argparse
from urllib.request import urlopen
import secp256k1 as ice

G = ice.scalar_multiplication(1)
N = ice.N
ZERO = ice.Zero

# Command-line argument parsing
parser = argparse.ArgumentParser(description='This tool retrieves ECDSA Signature r,s,z values from Bitcoin Address and attempts private key recovery if duplicate r values are found.',
                                 epilog='Enjoy the program! :)    Tips BTC: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at')
parser.add_argument("-a", help="Address to search for its rsz from the transactions", required=True)
args = parser.parse_args()
address = args.a

# Helper functions
def inv(a):
    return pow(a, N - 2, N)

def get_rs(sig):
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
    s = sig[8+rlen*2:]
    return r, s

def split_sig_pieces(script):
    sigLen = int(script[2:4], 16)
    sig = script[2+2:2+sigLen*2]
    r, s = get_rs(sig[4:])
    pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
    pub = script[4+sigLen*2+2:]
    assert(len(pub) == pubLen*2)
    return r, s, pub

def parseTx(txn):
    inp_list = []
    first = txn[0:10]
    cur = 10
    inp_nu = int(txn[8:10], 16)
    for m in range(inp_nu):
        prv_out = txn[cur:cur+64]
        var0 = txn[cur+64:cur+64+8]
        cur += 64 + 8
        scriptLen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*scriptLen]
        r, s, pub = split_sig_pieces(script)
        seq = txn[2+cur+2*scriptLen:10+cur+2*scriptLen]
        inp_list.append([prv_out, var0, r, s, pub, seq])
        cur += 10 + 2 * scriptLen
    rest = txn[cur:]
    return [first, inp_list, rest]

def get_rawtx_from_blockchain(txid):
    try:
        htmlfile = urlopen(f"https://blockchain.info/rawtx/{txid}?format=hex", timeout=20)
        return htmlfile.read().decode("utf-8")
    except Exception as e:
        print(f"[ERROR] Unable to fetch raw transaction {txid}: {e}")
        sys.exit(1)

def HASH160(pubk_hex):
    iscompressed = len(pubk_hex) < 70
    P = ice.pub2upub(pubk_hex)
    return ice.pubkey_to_h160(0, iscompressed, P).hex()

# Main function to scan and detect reused r values
def check_tx(address):
    print(f"[INFO] Checking transactions for address: {address}")
    txid = []
    cdx = []
    try:
        htmlfile = urlopen(f'https://mempool.space/api/address/{address}/txs/chain', timeout=60)
        while True:
            res = json.loads(htmlfile.read())
            if not res:
                break
            print(f"[INFO] Retrieved {len(res)} transactions.")
            for tx in res:
                for vin in tx["vin"]:
                    if "scriptpubkey_address" in vin["prevout"] and vin["prevout"]["scriptpubkey_address"] == address:
                        txid.append(tx["txid"])
                        cdx.append(vin["txid"])
            htmlfile = urlopen(f'https://mempool.space/api/address/{address}/txs/chain/{txid[-1]}', timeout=20)
    except Exception as e:
        print(f"[ERROR] Error fetching transactions for address {address}: {e}")
    return txid, cdx

# Retrieve reused r values and attempt private key recovery
def detect_reused_r_values_and_save(address):
    print(f"[INFO] Starting detection of reused r values for address: {address}")
    txid, cdx = check_tx(address)
    r_values = {}
    reused_r_data = []
    
    for c in range(len(txid)):
        print(f"[INFO] Processing transaction {c + 1}/{len(txid)}: {txid[c]}")
        rawtx = get_rawtx_from_blockchain(txid[c])
        try:
            parsed = parseTx(rawtx)
            for e in parsed[1]:  # each input in parsed transaction
                r = e[2]
                s = e[3]
                z = ice.get_sha256(ice.get_sha256(bytes.fromhex(e[4]))).hex()
                pub_key = e[4]
                
                # Check if r value is reused
                if r in r_values:
                    # Ensure s and z values differ for reuse
                    if r_values[r]["s"] != s and r_values[r]["z"] != z:
                        print(f"[INFO] Found valid reused r value with distinct s and z values: {r}")
                        reused_r_data.append({
                            "r": r,
                            "s1": r_values[r]["s"],
                            "s2": s,
                            "z1": r_values[r]["z"],
                            "z2": z,
                            "pub_key": pub_key
                        })
                    else:
                        print("[INFO] Skipping identical s and z values for reused r")
                else:
                    # Store first occurrence of r with its s and z values
                    r_values[r] = {"s": s, "z": z}
        except Exception as e:
            print(f"[WARNING] Skipping transaction {txid[c]} due to an error: {e}")

    # Save to file if reused r values found
    if reused_r_data:
        output_file = f"{address}_reused_r_data.json"
        with open(output_file, "w") as f:
            json.dump(reused_r_data, f, indent=4)
            print(f"[SUCCESS] Reused r values data saved to {output_file}")
    else:
        print("[INFO] No valid reused r values with distinct s and z found for this address.")

# Run detection
print("[INFO] Starting Program...")
detect_reused_r_values_and_save(address)
print("[INFO] Program Finished.")
