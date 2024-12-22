
import socket

host = 'localhost'
port = 4001

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    data = sock.recv(8)
    byte_array = list(data)
    print(byte_array)

    sock.close()


if __name__ == '__main__':
    main()