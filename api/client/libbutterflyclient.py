#!/usr/bin/env python
import pika
import sys
import json

args_len = len(sys.argv)
timeout = -1

#it's an int so if someday we want to use multiplie level of verbose like in ssh it will be easy to do
verbose = 0


def help(ret, prepend=""):
    print(
        prepend,
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
           "    help     print this and return 0\n",

           "sg":
           "butterfly sg subcommands:\n" +
           "    list    list security groups\n" +
           "    add     create one or more security groups\n" +
           "    del     remove one or more security groups\n" +
           "    rule    manage security group rules\n" +
           "    member  manage security group members",

           "dump":
           "usage: butterfly dump [options...]\n" +
           "Dump all butterfly configuration (nics and security groups) to "
           "stdout.\n" +
           "The generated data contains all requests ready to send to an other "
           "Butterfly\n" +
           "Example: \n" +
           "- butterfly dump > butterfly.dump\n" +
           "- butterfly shutdown\n" +
           "- start butterfly again\n" +
           "- butterfly request butterfly.dump"
}

commandes = {"nic" : {"list": BOOL, "add":
                      {"--ip": IP, "--dip": IP,  "--mac": MAC, "--dmac": MAC,
                       "--id": STRING, "--type": STRING, "--sg": STRING, "--vni": NUMBER,
                       "--bypass-filtering": BOOL, "--packet-trace": BOOL, "--trace-path": STRING}
},
             "dump" : BOOL,
             "sg": {"list": BOOL }
}

msgs = []

def mk_msg():
    ret = {"method0": None, "method1": None, 'params': []}
    msgs.append(ret)
    return ret


connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()

channel.queue_declare(queue='test')

def get_arg(i, error):
    if i >= args_len:
        sys.exit(error)
    return sys.argv[i]

def append_arg(params, t, i):
    param_name = get_arg(i, "missing argument").strip('-')
    if param_name in params:
        exit(param_name + " define twice")
    params.append(param_name)
    if t == BOOL:
        print("BOOL:", t)
        return i + 1
    elif t == STRING or t == IP or t == MAC:
        params.append(get_arg(i + 1, "missing argument"))
        print("append", t, sys.argv[i + 1])
        return i + 2
    elif t == NUMBER:
        params.append(int(get_arg(i + 1, "missing argument")))
        print("append int:", sys.argv[i + 1])
        return i + 2
    else:
        exit("unknow arguments")
    exit("Bad Argument" + sys.argv[i])

i = 1 # we skip program name
while i < args_len:
    a = sys.argv[i]
    print("a:", a)
    if a == "--help" or a == "-h":
        sys.exit(help(0))
    elif a == "--verbose" or a == "-v":
        verbose = 1
    elif a == "--timeout" or a == "-t":
        timeout = int(get_arg(i + 1, "timeout missing argument"))
        i += 2
        continue

    elif a in commandes:
        msg = mk_msg()
        m = commandes[a]
        msg["method0"] = a
        if type(m) is int:
            i = append_arg(msg["params"], m, i) + 1
            continue
        i += 1
        a = get_arg(i, "missing argument")
        if a in m:
            msg["method1"] = a

            if type(m[a]) is int:
                i = append_arg(msg["params"], m[a], i)
            elif type(m[a]) is dict:
                commade_good = False
                mp = m[a]
                i += 1
                ca = sys.argv[i]
                while ca in mp:
                    print(i, ca, mp[ca], sys.argv[i])
                    if i == args_len:
                        break
                    commade_good = True
                    i = append_arg(msg["params"], mp[ca], i)
                    ca = sys.argv[i]

                if commade_good == False:
                    sys.exit("invalide argument : '" + ca + "'\n" +
                             subhelper[msg["method0"]][msg["method1"]])
                continue
        else:
            sys.exit(helpers[msg["method0"]])
        print(msg["method1"])
    elif a != "--":
        exit(help(1, prepend="unknow argument:" + a + "\n"))
    i += 1

print("verbose: ", verbose)

for msg in msgs:
    payload = json.dumps ({
        "method": [msg["method0"], msg["method1"]],
        "params": msg["params"],
        "jsonrpc": "2.0",
        "id": 0,
    })

    print(payload)
    channel.basic_publish(exchange='amq.direct',
                          routing_key='test',
                          body=payload)

    print(" [x] Sent 'msg!'")

connection.close()
