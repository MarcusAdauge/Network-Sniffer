import csv
from socket import inet_ntoa

class IP_Packet:
    def __init__(self, rawData, vrs, IHL, TOS, totalLen, ID, flags,
                       fragOffset, ttl, prot, crc, src, dst):
        self.rawData = rawData
        self.version = vrs
        self.IHL = IHL
        self.TOS = TOS
        self.totalLenght = totalLen
        self.ID = ID
        self.flags = flags
        self.fragmentOffset = fragOffset
        self.TTL = ttl
        self.protocolNr = prot
        self.protocolName = self.__setProtocolName(prot)
        self.checkSum = crc
        self.src = src
        self.dst = dst

    def __setProtocolName(self, protocolNr):
        protocolsFile = open('Protocols.csv', 'r')
        reader = csv.reader(protocolsFile)
        protocols = {int(rows[0]): rows[1:] for rows in reader}
        return ', '.join(protocols[protocolNr])


    def display(self):
        # Type Of Service values
        precedence = {0: "0 = Routine", 1: "1 = Priority", 2: "2 = Immediate", 3: "3 = Flash", 4: "4 = Flash",
                      5: "5 = CRITIC/ECP", 6: "6 = Internetwork control", 7: "7 = Network control"}
        delay = {0: "0 = Normal delay", 1: "1 = Low delay"}
        throughput = {0: "0 = Normal throughput", 1: "1 = High throughput"}
        reliability = {0: "0 = Normal reliability", 1: "1 = High reliability"}
        cost = {0: "0 = Normal monetary cost", 1: "1 = Minimize monetary cost"}

        # Flags values
        flagR = {0: '0 = reserved'}
        flagDF = {0: '0 = Fragment if necessary', 1: '1 = Do not fragment'}
        flagMF = {0: '0 = No more fragments', 1: '1 = More fragments follow this fragment'}

        print 'An IP packet with the size %i bytes was captured' % self.totalLenght
        print 'Raw data:\n' + self.rawData + '\n'

        print ' ' + '-'*72
        print '|\t\t\t\tIP HEADER\t\t\t\t |'
        print '|' + '='*72 + '|'
        print '|' + '{:>30}'.format('Version |') + "  " + str(self.version)
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('Internet Header Length |') + "  " + str(self.IHL * 4) + ' bytes'
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('|') + '{:>15}'.format('precedence:') + \
              "  " + precedence[self.TOS['precedence']]
        print '|' + '{:>30}'.format('|') + '{:>15}'.format('delay:') + "  " + delay[self.TOS['delay']]
        print '|' + '{:>30}'.format('Type of Services |') + '{:>15}'.format('throughput:') + \
              "  " + throughput[self.TOS['throughput']]
        print '|' + '{:>30}'.format('|') + '{:>15}'.format('reliability:') + \
              "  " + reliability[self.TOS['reliability']]
        print '|' + '{:>30}'.format('|') + '{:>15}'.format('cost:') + \
              "  " + cost[self.TOS['cost']]
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('Total Lenght |') + "  " + str(self.totalLenght) + " bytes"
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('ID |') + "  " + str(self.ID)
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('|') + '{:>5}'.format('R:') + "  " + flagR[self.flags['R']]
        print '|' + '{:>30}'.format('Flags |') + '{:>5}'.format('DF:') + "  " + flagDF[self.flags['DF']]
        print '|' + '{:>30}'.format('|') + '{:>5}'.format('MF:') + "  " + flagMF[self.flags['MF']]
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('Fragment Offset |') + "  " + str(self.fragmentOffset)
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('TTL (Time To Live) |') + "  " + str(self.TTL)
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('Protocol |') + "  " + str(self.protocolName)
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('Header checksum |') + "  " + str(self.checkSum)
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('Source Address |') + "  " + inet_ntoa(self.src)
        print '|' + '-'*72 + '|'
        print '|' + '{:>30}'.format('Destination Address |') + "  " + inet_ntoa(self.dst)
        print ' ' + '-'*72 + '\n'




