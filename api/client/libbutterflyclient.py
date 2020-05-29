#!/usr/bin/env python
import pika
import sys
import json

args_len = len(sys.argv)
timeout = -1

#it's an int so if someday we want to use multiplie level of verbose like in ssh it will be easy to do
verbose = 0


def help(ret):
    print(
        "global options:\n",
        "    --verbose, -v   show details of each operation\n",
        "    --timeout, -t   set a timeout for each operations in ms\n",
        "    --key, -k       path to encryption key (32 raw bytes)\n"
    )
    return ret

NUMBER = 1
IP = 2
MAC = 3
STRING = 4
BOOL = 5

subhelper = {"nic":
             {
                 "list": "usage: butterfly nic list",
                 "add":
                 "usage: butterfly nic add [options...]" +
                 "options:\n" +
                 "    --ip IP             virtual interface's ip (v4 or v6)\n" +
                 "    --mac MAC           virtual interface's mac (mandatory)\n" +
                 "    --id ID             interface's id (mandatory)\n" +
                 "    --type TYPE         nic type (VHOST_USER_SERVER, BENCH or " +
                 "    TAP default: VHOST_USER_SERVER)\n" +
                 "    --btype BENCH_TYPE  bench type ICMP_SND_LIKE or " +
                 "ICMP_RCV_LIKE (for bench)\n" +
                 "    --dip IP            interface's dest ip (for bench)\n" +
                 "    --dmac MAC          interface's dest mac (for bench)\n" +
                 "    --vni VNI           virtual network id < 2^26 (mandatory)\n" +
                 "    --enable-antispoof  enable antispoof protection (default: off)\n"
                 "    --packet-trace      true/false  trace a nic or not " +
                 "    (default: use server behaviour)\n" +
                 "    --trace-path PATH    where to store pcap file if packet-trace" +
                 "    was set true (default: PATH = /tmp/butterfly-PID-nic-NICID.pcap)\n" +
                 "    --bypass-filtering  remove all filters and protection"
             }
}

helpers = {"nic":
        "butterfly nic subcommands:\n"+
        "    list     list all nics id\n"+
        "    stats    show nic statistics\n"+
        "    details  prints nics's details\n"+
        "    sg       manage security groups attached to a nic\n"+
        "    add      create a new nic\n"+
        "    del      remove nic(s)\n"+
        "    update   update a nic\n"+
        "    help     print this and return 0\n"
}

commandes = {"nic" : {"list": BOOL, "add":
                      {"--ip": IP, "--dip": IP,  "--mac": MAC, "--dmac": MAC,
                       "--id": STRING, "--type": STRING, "--sg": STRING, "--vni": NUMBER,
                       "--bypass-filtering": BOOL, "--packet-trace": BOOL, "--trace-path": STRING}
},
             "dump" : BOOL
}

method0 = "NOPE"
method1 = None
params = []

connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()

channel.queue_declare(queue='test')

def append_arg(params, t, i):
    if t == BOOL:
        return i
    elif t == STRING:
        params.append(sys.argv[i])
        return i + 1
    exit("Bad Argument")

i = 0
while i < args_len:
    a = sys.argv[i]
    if a == "--help" or a == "-h":
        sys.exit(help(0))
    if a == "--verbose" or a == "-v":
        verbose = 1
    if a == "--timeout" or a == "-t":
        if i + 1 == args_len:
            sys.exit("timeout missing argument")
        timeout = int(sys.argv[i + 1])
        i += 2
        continue

    if a in commandes:
        m = commandes[a]
        print("COMMAND:", a)
        method0 = a
        if type(m) is int:
            i = append_arg(params, m, i) + 1
            continue
        i += 1
        a = sys.argv[i]
        if a in m:
            method1 = a
            i += 1
            print(m[a])

            if type(m[a]) is int:
                i = append_arg(params, m[a], i)
            elif type(m[a]) is dict:
                commade_good = False
                ca = sys.argv[i]
                print(ca, m[a])
                while ca in m[a]:
                    i += i
                    if i == args_len:
                        break
                    commade_good = True
                    print("key", ca.strip('-'))
                    ca = sys.argv[i]

                if commade_good == False:
                    sys.exit("invalide argument : '" + ca + "'\n" + subhelper[method0][method1])
                print("My tralala !")
        else:
            sys.exit(helpers[method0])
        print(method1)
    i += 1

payload = json.dumps ({
    "method": [method0, method1],
    "params": params,
    "jsonrpc": "2.0",
    "id": 0,
})

print(payload)
channel.basic_publish(exchange='amq.direct',
                      routing_key='test',
                      body=payload)

print(" [x] Sent 'msg!'")

connection.close()
