import socket
import scapy.all
import hashlib
from brute import brute
import httplib2

# Constants:
TCP_IP = '152.66.249.144'
TCP_KNOCK_PORT_1 = 1337
TCP_KNOCK_PORT_2 = 2674
TCP_KNOCK_PORT_3 = 4011
BUFFER_SIZE = 1024
NEPTUN = "FIBRPN"
# Port knocking:
packet1 = scapy.all.IP(dst=TCP_IP) / scapy.all.TCP(dport=TCP_KNOCK_PORT_1)
scapy.all.send(packet1)
packet2 = scapy.all.IP(dst=TCP_IP) / scapy.all.TCP(dport=TCP_KNOCK_PORT_2)
scapy.all.send(packet2)
packet3 = scapy.all.IP(dst=TCP_IP) / scapy.all.TCP(dport=TCP_KNOCK_PORT_3)
scapy.all.send(packet3)
# First request:
TCP_PORT = 8888
connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.connect((TCP_IP, TCP_PORT))
neptun_request_data = connection.recv(BUFFER_SIZE).decode()
print(neptun_request_data)
connection.send(NEPTUN.encode())
greeting_data = connection.recv(BUFFER_SIZE).decode()
print(greeting_data)
equation_data = connection.recv(BUFFER_SIZE).decode()
equation_lines = equation_data.split('\n')
for line in equation_lines:
    print(line)
# No. of equations:
equation_no = int(equation_lines[0].split()[4])

# Solve function:
def solve_equation(equation):
    members = equation.split()
    result = 0
    operator = 1
    del members[0]
    for member in members:
        try:
            tmp = int(member)
            result += operator * tmp
        except:
            if member == '-':
                operator = -1
            elif member == '+':
                operator = 1
    return str(result)

# First equation:
temp_equation = equation_lines[2]
connection.send(solve_equation(temp_equation).encode())

# Other equations:
result = 0
for i in range(1, equation_no):
    temp_equation = connection.recv(BUFFER_SIZE).decode()
    result = solve_equation(temp_equation)
    connection.send(result.encode())

# Message:
temp_response = connection.recv(BUFFER_SIZE).decode()
print(temp_response)

# sha1 instructions:
temp_response = connection.recv(BUFFER_SIZE).decode()
print(temp_response)

# sha1:
neptun_value = NEPTUN + str(result)
sha1_value = hashlib.sha1(neptun_value.encode()).hexdigest()
connection.send(sha1_value.encode())

# Messages:
temp_response = connection.recv(BUFFER_SIZE).decode()
print(temp_response)
temp_response = connection.recv(BUFFER_SIZE).decode()
print(temp_response)
# BruteForce 0000 start (https://github.com/rdegges/brute/issues/7 javítás alkalmazásával):
for force in brute(length=10, letters=True, numbers=True, symbols=False):
    temp_neptun_value = neptun_value + force
    if hashlib.sha1(temp_neptun_value.encode()).hexdigest().startswith("0000"):
        break

print("bruteforced!")
print("value: " + str(temp_neptun_value))
print("sha1: " + str(hashlib.sha1(temp_neptun_value.encode()).hexdigest()))
connection.send(temp_neptun_value.encode())

# Messages:
temp_response = connection.recv(BUFFER_SIZE).decode()
print(temp_response)
temp_response = connection.recv(BUFFER_SIZE).decode()
print(temp_response)
temp_response = connection.recv(BUFFER_SIZE).decode()
print(temp_response)

# auth with certs:
key_path = input("Path to key file: ")
cert_path = input("Path to cert file: ")
if key_path == "":
    key_path = "/Users/dominik/Downloads/clientkey.pem"
if cert_path == "":
    cert_path = "/Users/dominik/Downloads/clientcert.pem"
http = httplib2.Http(disable_ssl_certificate_validation=True)
http.add_certificate(key_path, cert_path, "")
response, content = http.request("https://" + TCP_IP + "/", "GET", headers={'user-agent': 'CrySyS'})
print("Response: ")
print(response)
print("Content:")
print(content)

connection.close()