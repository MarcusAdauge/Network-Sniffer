from struct import unpack

class IP_Parser:
    def __init__(self, rawData):
        self.data = self.unpackData(rawData)

    def unpackData(self, packedData):
        return unpack('!BBHHHBBH4s4s', packedData[:20])

    def getVersion(self):
        return self.data[0] >> 4

    def getIHL(self):
        return self.data[0] & 0xF

    def getTOS(self):
        TOS = {}
        TOS['precedence'] = self.data[1] >> 5
        TOS['delay'] = (self.data[1] & 0x10) >> 4
        TOS['throughput'] = (self.data[1] & 0x8) >> 3
        TOS['reliability'] = (self.data[1] & 0x4) >> 2
        TOS['cost'] = (self.data[1] & 0x2) >> 1
        return TOS

    def getTotalLength(self):
        return self.data[2]

    def getID(self):
        return self.data[3]

    def getFlags(self):
        flags = {}
        flagsBits = self.data[4] >> 13
        flags['R'] = flagsBits >> 2
        flags['DF'] = (flagsBits & 0x2) >> 1
        flags['MF'] = flagsBits & 0x1
        return flags

    def getFragmentOffset(self):
        return self.data[4] & 0x1FFF

    def getTTL(self):
        return self.data[5]

    def getProtocol(self):
        return self.data[6]

    def getCheckSum(self):
        return self.data[7]

    def getSRC(self):
        return self.data[8]

    def getDST(self):
        return self.data[9]
