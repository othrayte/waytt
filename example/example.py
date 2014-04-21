import os
import time
from multiprocessing import Process, Pipe
import ipaddress

import waytt

try:
    import humanize
    have_humanise = True
except:
    have_humanise = False

data = {}

def clearTerm():
    """ Utility function to clear the terminal window """
    os.system('cls' if os.name=='nt' else 'clear')

def listener(packetIn):
    """ Sets up waytt to listen for network traffic """
    adaptors = waytt.adaptors()
    print("Found %i network adaptor(s)." % len(adaptors))
    print("Going to monitor %s" % adaptors[0][1])
    def logTraffic(*args): # (down, up, src, dst)
        """
        Gets called for !!EVERY!! ipv4 packet, must be efficient
        Arguments are in the form (down, up, src, dst)
        """
        try:
            packetIn.send(args)
        except Exception as e:
            print(e)
    
    # Start listening to the first adaptor, igoring traffic to or from the 192.168.X.X subnet, calls logTraffic for each packet seen     
    waytt.start([adaptors[0][0]], int(ipaddress.IPv4Address("192.168.0.0")), int(ipaddress.IPv4Address("255.255.0.0")), logTraffic)

def display(data):
    """ Display collated traffic totals to console"""
    clearTerm()
    for remote in data.keys():
        if remote not in data:
            return
        ip = ipaddress.ip_address(remote)
        d = data[remote]['down']
        u = data[remote]['up']
        if have_humanise:
            print("%s:   \t%s down,    \t%s up" % (str(ip), humanize.naturalsize(d), humanize.naturalsize(u)))
        else:
            print("%s:   \t%i down,    \t%i up" % (str(ip), d, u),flush=True)

if __name__ == '__main__':
    # Don't use a Queue for this as data may be held in the queue until enough arrives for it to be released
    # this can cause nearly 30s delay from when the info arrived to it being seen here
    packetOut, packetIn  = Pipe(False)
    process = Process(target=listener, args=(packetIn,))
    process.start()

    nextTime = time.time()+1

    while True:
        if packetOut.poll(): # Are there any packets to log
            packet = packetOut.recv()
            
            if packet[0] > 0: # down is > 0 then inbound
                remote = packet[2] # remote is src
                if remote not in data:
                    data[remote] = {'down': packet[0], 'up': 0}
                else:
                    data[remote]['down'] += packet[0]
            else: # assume outbound
                remote = packet[3] # remote is dst
                if remote not in data:
                    data[remote] = {'down': 0, 'up': packet[1]}
                else:
                    data[remote]['up'] += packet[1]
        else:
            if time.time() >= nextTime:
                nextTime += 1
                display(data)
            else:
                time.sleep(0.001)

