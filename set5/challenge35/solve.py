""" 
    Implement DH with negotiated groups, and break with malicious "g" parameters
"""

"""
Attacks:

* g = 1   -> Shared Key = 1
* g = p   -> Shared Key = 0
* g = p-1 -> Shared Key = 1 || p - 1

"""