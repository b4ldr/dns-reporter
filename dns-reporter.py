#!/usr/bin/env python
import SocketServer
import struct
import socket
import argparse
import logging
import time
import yaml
import json
import os
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.txtbase
import dns.flags
import scapy.all

#class DnsReporterServer(SocketServer.ThreadingUDPServer):
class DnsReporterServer(SocketServer.UDPServer):
    '''
    SocketServer.ThreadingUDPServer 

    Instance variables:
    
    - RequestHandlerClass
    '''
    def __init__(self, server_address, RequestHandlerClass, domain):
        #SocketServer.ThreadingUDPServer.__init__(self,server_address,RequestHandlerClass)
        SocketServer.UDPServer.__init__(self,server_address,RequestHandlerClass)
        self.domain = domain
        self.logger = logging.getLogger('dns-reporter.DnsReporter')

class DnsReporterHanlder(SocketServer.BaseRequestHandler):
    '''
    Base Handeler class 
    '''

    message = None
    nsid = None
    serial = None
    data = None
    incoming = None
    node_name = None
    COMMANDS = ['whoami', 'trace']

    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def _whoami(self, answer, rdclass, rdtype):
        answer.add(dns.rdtypes.txtbase.TXTBase( rdclass, rdtype, self.client_address[0]))
        return answer

    def _trace(self, answer, rdclass, rdtype):
        answer.add(dns.rdtypes.txtbase.TXTBase(
            rdclass, rdtype, '0:{}'.format(socket.gethostname())))
        ans, unans = scapy.all.sr(scapy.all.IP(dst=self.client_address[0],
            ttl=(1,24))/scapy.all.UDP(
            dport=self.client_address[1],sport=53),timeout=3)
        for snd,rcv in ans:
            string = '{}:{}'.format(snd.ttl, rcv.src)
            answer.add(dns.rdtypes.txtbase.TXTBase(
                rdclass, rdtype, string))
        return answer

    def process_command(self, command, message):
        '''run a the command and add an answer'''
        self.server.logger.debug('command_from:{}: {}'.format(
            self.client_address, command))
        if command not in self.COMMANDS:
            message.set_rcode(dns.rcode.NXDOMAIN)
        else:
            qname   = message.question[0].name
            rdclass = message.question[0].rdclass
            rdtype  = message.question[0].rdtype
            message.answer = [dns.rrset.RRset(qname,rdclass,rdtype)]
            message.answer[0] = {
                'whoami': self._whoami,
                'trace': self._trace
            }.get(command)(message.answer[0], rdclass, rdtype)

            #message.answer[0].add(dns.rdtypes.txtbase.TXTBase( rdclass, rdtype, 
            #    self{ 'whoami': whoami}.get(command)))
        return message

    def parse_dns(self):
        '''
        parse the data package into dns elements
        '''
        message = None
        data    = str(self.request[0]).strip()
        command = None
        #incoming Data
        try:
            message = dns.message.from_wire(data)
        except dns.name.BadLabelType:
            #Error processing lable (bit flip?)
            return False 
        except dns.message.ShortHeader:
            #Recived junk
            return False
        else:
            if (message.flags & dns.flags.QR) == 0:
                message.flags |= dns.flags.QR
                message.flags |= dns.flags.AA
                message.flags &= ~dns.flags.CD
                if len(message.question) != 1:
                    message.set_rcode(dns.rcode.NOTIMP)
                    return message.to_wire()

                qname   = message.question[0].name.to_text()
                rdclass = message.question[0].rdclass
                rdtype  = message.question[0].rdtype
                self.server.logger.debug('query_from:{}: {} {}'.format(
                    self.client_address, qname, rdclass, rdtype))

                if rdtype != dns.rdatatype.TXT or rdclass != dns.rdataclass.IN:
                    message.set_rcode(dns.rcode.NOTIMP)
                    return message.to_wire()

                if not qname.endswith(self.server.domain): 
                    message.set_rcode(dns.rcode.REFUSED)
                    return message.to_wire()
                else:
                    #-1 to get rid of the extra dot'
                    command = qname[:-len(self.server.domain)-1]
                    message = self.process_command(command, message)
                
                return message.to_wire()
        return self.request[0]

    def handle(self):
        '''
        RequestHandlerClass handle function
        handler listens for dns packets
        '''
        answer = self.parse_dns()
        incoming = self.request[1] 
        if answer:
            '''send response'''
            incoming.sendto(answer, self.client_address)


def main():
    ''' main function for using on cli'''
    parser = argparse.ArgumentParser(description='dns spoof monitoring script')
    parser.add_argument('-v', '--verbose', action='count', help='Increase verbosity')
    parser.add_argument('-l', '--listen', metavar="0.0.0.0:53", 
            default="0.0.0.0:53", help='listen on address:port ')
    parser.add_argument('-d', '--domain', required=True,
            help='authorative domain')
    args = parser.parse_args()

    log_level = logging.ERROR
    if args.verbose == 1:
        log_level = logging.WARN
    elif args.verbose == 2:
        log_level = logging.INFO
    elif args.verbose > 2:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)
   
    if args.domain[-1] != '.':
        args.domain += '.'
    host, port = args.listen.split(":")
    server = DnsReporterServer((host, int(port)), DnsReporterHanlder, args.domain)
    server.serve_forever()

if __name__ == "__main__":
    main()
