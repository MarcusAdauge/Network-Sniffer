from socket import *
from IP_Parser import IP_Parser
from IP_Packet import IP_Packet
from struct import unpack
import sys
from time import sleep


def recieveData(sock):
    raw_data = ''
    try:
        raw_data = sock.recvfrom(65565)
    except timeout:
        raw_data = ''
    except:
        print 'Failed to recieve data!'
        sys.exit(0)
    return raw_data[0]


def parseUDP(packedData):
    udpHeader = unpack('!HHHH', packedData[20:28])
    print '{:>20}'.format("UDP Source Port: ") + str(udpHeader[0])
    print '{:>20}'.format("UDP Dest Port: ") + str(udpHeader[1])
    print '{:>20}'.format("UDP Length: ") + str(udpHeader[2]) + ' bytes'
    print '{:>20}'.format("UDP Checksum: ") + str(udpHeader[3])

    udpData = packedData[28:]
    print '{:>20}'.format('UDP Payload: ') + '\n' + '-'*50
    print udpData


if __name__ == "__main__":

    HOST = gethostbyname(gethostname())  # Translate the host name to IPv4 address format
    try:
        s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)  # create a raw socket [AF_INET = use IPv4]
    except socket.error, (value, message):
        print 'Failed to create the socket: ' + message
        sys.exit(-1)
    s.bind((HOST, 0))                          # bind the socket to the public interface
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)  # Include IP headers

    s.ioctl(SIO_RCVALL, RCVALL_ON)  # receive all packages

    while True:
        data = recieveData(s)
        parser = IP_Parser(data)
        ipPacket = IP_Packet(data, parser.getVersion(), parser.getIHL(), parser.getTOS(),
                             parser.getTotalLength(), parser.getID(), parser.getFlags(),
                             parser.getFragmentOffset(), parser.getTTL(), parser.getProtocol(),
                             parser.getCheckSum(), parser.getSRC(), parser.getDST())

        ipPacket.display()
        if ipPacket.protocolNr == 17:
            parseUDP(data)
        else:
            print 'Payload (%s):\n' %ipPacket.protocolName + data[20:] + '\n'
        print '#'*80 + '\n'
        sleep(2)

    # disabled promiscuous mode
    s.ioctl(SIO_RCVALL, RCVALL_OFF)