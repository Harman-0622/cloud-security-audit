import hashlib
import json

def generate_report_hash(payload_dict):
    """
    Takes a Python dictionary, normalizes it (sort_keys=True ensures 
    the dictionary is always ordered the exact same way), and returns a SHA-256 hash.
    """
    # Convert dictionary to a string with zero whitespace and alphabetically sorted keys
    canonical_string = json.dumps(payload_dict, sort_keys=True, separators=(',', ':'))
    
    # Compute the SHA-256 digest
    digest = hashlib.sha256(canonical_string.encode('utf-8')).hexdigest()
    
    return digest