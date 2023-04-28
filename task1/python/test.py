import hashlib
temp_sha1 = hashlib.sha1("NEPTUN-10001".encode())
print(temp_sha1.hexdigest())