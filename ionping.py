"""
Created by Advait Menon
Version 0.9
Last Updated: 2023-04-10
"""
import os
import socket
import struct
import ipaddress
import time
import argparse
import argcomplete
from concurrent import futures
import sys
from queue import Queue
from threading import Thread

"""
Input file format example:
192.168.0.0/16;
172.16.0.0/12;
10.0.0.0/8;1,2,3,10,100,254
"""

# ICMP ECHO REQUEST / REPLY CONSTANTS
_header_byte_order = "!BBHHH"
_ECHO_REQ = 8

# Default Settings
_default_timeout = 2.0
_max_threads = 4
timeout = _default_timeout

# Queue for handling write requests from multiple threads
writer_queue = Queue()

"""

ECHO REQUEST AND REPLY STRUCTURE

   0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-
"""

"""
build a payload for requests. Default Data is blank. It's best left this way to avoid IDS from mistaking it for a 
C2 Beacon
"""


class ICMP_ECHO():
    def __init__(self, icmp_id=0, sequence=0, data=b''):
        self.icmp_id = icmp_id
        self.sequence = sequence
        self.data = data
        icmp_header = struct.pack(_header_byte_order, _ECHO_REQ, 0, 0, self.icmp_id, self.sequence)
        payload = icmp_header + data
        checksum = 0
        for i in range(0, len(payload), 2):
            word = (payload[i] << 8) + payload[i + 1]
            checksum += word
            checksum = (checksum & 0xffff) + (checksum >> 16)
        self.checksum = ~checksum & 0xffff
        # self.checksum = self.calculate_checksum(icmp_header + self.data)
        self.header = struct.pack(_header_byte_order, _ECHO_REQ, 0, self.checksum, self.icmp_id, self.sequence)
        self.payload = self.header + self.data

    def payload(self):
        return self.header + self.data

    def __str__(self):
        return f'ICMP ECHO REQUEST: Checksum: {self.checksum}, ID: {self.icmp_id}, Sequence Number: {self.sequence}, Data: {self.data}'

    def __repr__(self):
        return f'{self.__class__.__name__}({self.checksum!r}, {self.icmp_id!r}, {self.sequence!r}, {self.data!r}'

    def __len__(self):
        return len(self.header + self.data)


# Check if response matches expected format and address
def validate_echo_response(icmp_response, icmp_id, address):
    type, code, checksum, id, seq = struct.unpack(_header_byte_order, icmp_response)
    if type == 0 and code == 0 and id == icmp_id:
        return True
    else:
        return False


# Code to ping scan one subnet. Short circuits if a match is found.
def subnet_queue(subnet, suffix_list):
    if suffix_list is None:
        suffix_list = [f'.{i}' for i in range(256)]
    print(f'[i] Scanning Subnet: {subnet}')
    try:
        if "/" in subnet:  # Assume it's /24 and strip it
            subnet = subnet.split("/")[0]
        for suffix in suffix_list:
            address = '.'.join(subnet.split(".")[0:-1]) + suffix
            if send_ping(address):
                print(f'[+] Subnet {subnet}/24 is live')
                writer_queue.put(f'{subnet}/24\n')
                break # If a match is found, stop doing more scans of the same subnet
            # Check if at last value in subnet
            if suffix == suffix_list[:-1]:
                print(f'[-] Subnet {subnet}/24 is not live')
    except KeyboardInterrupt:
        sys.exit(1)


# Code to send a ping and return if a response has been received.
def send_ping(address):
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_socket.settimeout(_default_timeout)
    echo_request = ICMP_ECHO()
    icmp_socket.sendto(echo_request.payload, (address, 0))

    start_time = time.time()
    while True:
        try:
            packet, addr = icmp_socket.recvfrom(1024)
            icmp_header = packet[20:28]
            if validate_echo_response(icmp_header, echo_request.icmp_id, addr):
                print(f'[+] Received ICMP response from {addr}/n')
                return True
            else:
                print(f'[!] Received Unexpected response from {addr}/n')
                print(icmp_header)
                return False
        except socket.timeout:
            # Handle timeout error
            elapsed_time = time.time() - start_time
            if elapsed_time >= _default_timeout:
                print(f'[-]Timeout waiting for ICMP response from {address}/n')
                return False


# Thread to write stuff in queue. Writes in real time in case the program is interrupted / crashes
def file_writer(queue, file_handle):
    while True:
        output = writer_queue.get()
        file_handle.write(output)
        file_handle.flush()
        writer_queue.task_done()


def main():
    # Argument Parsing
    parser = argparse.ArgumentParser(description='A Python program to perform a ping scan.')
    parser.add_argument('-iL', '--subnet-list', nargs='+', required=True, help='Input file for subnet and port mapping')
    parser.add_argument('-o', '--output', nargs='+', required=True, help='Output txt file')
    parser.add_argument('-t', '--timeout', help='Timeout duration in seconds (Default 2 seconds)', type=int, default=2)
    parser.add_argument('-T', '--threads', help='Number of threads to run (Default 4 threads)', type=int, default=4)
    argcomplete.autocomplete(parser)  # argcomplete
    args = parser.parse_args()
    args.subnet_list = ' '.join(args.subnet_list)
    args.output = ' '.join(args.output)

    # Argument Validation
    assert type(args.timeout) is int

    if args.timeout < 1:
        print(f'[e] Specified timeout must be at least 1 second')
        exit(1)

    if args.threads < 1:
        print(f'[e] must use at least 1 thread')
        exit(1)

    if args.threads > _max_threads:
        print(f'[e] thread size cannot be bigger than {_max_threads}! (Can cause serious issues)')
        exit(1)

    if not os.path.exists(args.subnet_list):
        print(f'[e] File {args.subnet_list} could not be found.')
        exit(1)

    # Set arguments
    file_name = args.output
    global timeout
    timeout = args.timeout

    # Output file name adjustments
    if os.path.splitext(file_name)[-1] != '.txt':
        print(f'[w] Specified output \'{file_name}\' does not end in .txt. .txt will be automatically appended')
        file_name = file_name + '.txt'

    if os.path.exists(file_name):  # if file name exists add a (1) to it
        n = 1
        while os.path.exists(f'{os.path.splitext(file_name)[0]}({n}){os.path.splitext(file_name)[1]}'):
            n += 1
        print(
            f'[w] {file_name} exists already. Writing to {os.path.splitext(file_name)[0]}({n}){os.path.splitext(file_name)[1]}')
        file_name = f'{os.path.splitext(file_name)[0]}({n}){os.path.splitext(file_name)[1]}'

    # Read and parse the input mapping
    parsing_map = open(args.subnet_list, 'r').read().splitlines()
    subnet_list = []  # The list of arguments to pass to the subnet_queue function. It's a tuple
    for mapping in parsing_map:
        cidr_range = mapping.split(";")[0]
        host_range = 0
        if mapping.split(";")[1] == "" or mapping.split(";")[1] is None: # If hosts aren't specified just default to all
            host_range = [f".{i}" for i in range(256)]
        else:
            host_range = [f".{i}" for i in mapping.split(";")[1].split(",")]

        # Convert list to
        subnet_list.extend([(str(ipaddress.IPv4Network(ip)), host_range) for ip in
                            ipaddress.ip_network(cidr_range).subnets(new_prefix=24)])

    # Thread Handling
    with open(file_name, 'a', encoding='utf-8') as handle:
        # Establish a thread that processes write requests from the queue to output to file
        writer = Thread(target=file_writer, args=(writer_queue, handle), daemon=True)
        writer.start()
        workers = min(args.threads, len(subnet_list))  # If the list of subnets is shorter, use that amount of threads instead
        with futures.ThreadPoolExecutor(workers) as executor:  # run everything
            executor.map(lambda p: subnet_queue(*p), subnet_list)  # The lambda passes unpacked tuple into subnet_queue
        # Close the writing thread
        writer_queue.join()
    print('[i] finished execution')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
