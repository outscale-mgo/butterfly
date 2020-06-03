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
STRING_LIST = 6

nic_add_update_help = """options:
    --ip IP             virtual interface's ip (v4 or v6)
    --mac MAC           virtual interface's mac (mandatory)
    --id ID             interface's id (mandatory)
    --type TYPE         nic type (VHOST_USER_SERVER, BENCH or TAP default: VHOST_USER_SERVER)
    --btype BENCH_TYPE  bench type ICMP_SND_LIKE or ICMP_RCV_LIKE (for bench)
    --dip IP            interface's dest ip (for bench)
    --dmac MAC          interface's dest mac (for bench)
    --vni VNI           virtual network id < 2^26 (mandatory)
    --enable-antispoof  enable antispoof protection (default: off)
    --packet-trace      true/false  trace a nic or not (default: use server behaviour)
    --trace-path PATH    where to store pcap file if packet-trace
    was set true (default: PATH = /tmp/butterfly-PID-nic-NICID.pcap)
    --bypass-filtering  remove all filters and protection
"""

subhelper = {"nic":
             {
                 "list": "usage: butterfly nic list",
                 "add": "usage: butterfly nic add [options...]\n" +
                 nic_add_update_help,
                 "update": "usage: butterfly nic update [options...]\n" +
                 nic_add_update_help,
                 "sg":
                 "butterfly nic sg subcommands:\n" +
                 "    list  list security groups attached to a nic\n" +
                 "    add   add one or more security group to a nic\n" +
                 "    del   removes one or more security group of a nic\n" +
                 "    set   update all security groups of a nic"
             },
             "sg": {
                 "member": """
butterfly sg member subcommands:"
    list  list members of a security group
    add   add member to a security group
    del   remove member of a security group
                 """,
                 "rule": """
butterfly sg rule subcommands:
    list  list security group rules

    add   Add a new firewalling rule inside a security group
              usage: butterfly sg rule add SG [options...]
                 options:
                 --dir DIRECTION    rule direction 'in' or 'out' (default: in)"
                 --ip-proto PROTO   IP protocol to allow (mandatory)"
                 --port PORT        open a single port"
                 --port-start PORT  port range start
                 --port-end PORT    port range end
                 --cidr CIDR        adress mask to allow in CIDR format
                 --sg-members SG    security group members to allow

                 PROTO:
                 Must be 'tcp', 'udp', 'icmp', a number between 0 and 255
                 or 'all' to allow all protocols
                 PORT:
                 if you set udp or tcp in protocol, you can set a port between
                 0 and 65535
                 Notes: you MUST set either --cidr or --sg-members

    del   Remove a firewalling rule from a security group
                 first usage: butterfly sg rule del SG RULE_HASH
                 You can get RULE_HASH from sg rule list subcommand
                 """
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
                       "--bypass-filtering": BOOL, "--packet-trace": BOOL, "--trace-path": STRING},
                      "stats": STRING,
                      "details": STRING,
                      "sg": {
                          "list": BOOL,
                          "add": STRING_LIST,
                          "del": STRING_LIST,
                          "set": STRING_LIST,
                      },
                      "del": STRING_LIST,
                      "update": {
                          "--ip": IP, "--dip": IP,  "--mac": MAC, "--dmac": MAC,
                          "--id": STRING, "--type": STRING, "--sg": STRING, "--vni": NUMBER,
                          "--bypass-filtering": BOOL, "--packet-trace": BOOL, "--trace-path": STRING
                      }
},
             "dump" : BOOL,
             "sg": {"list": BOOL,
                    "member": {
                        "list": STRING,
                        "add": STRING_LIST,
                        "del": STRING_LIST
                    },
                    "add": STRING_LIST,
                    "del": STRING_LIST,
                    "rule": {
                        "list": STRING,
                        "add": {
                            "--dir": STRING,
                            "--ip-proto": STRING,
                            "--port": NUMBER,
                            "--port-start": NUMBER,
                            "--port-end": NUMBER,
                            "--cidr": STRING,
                            "--sg-members": STRING_LIST
                        },
                        "del": STRING_LIST
                    }
             },
             "shutdown" : BOOL,
             "status": BOOL
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
    params.append(param_name)
    print(param_name, type(t))

    if type(t) == dict:
        j = i + 1
        a = get_arg(j, "wesh - 0")
        while a in t:
            print("while", a, "in ", t[a])
            j = append_arg(params, t[a], j)
            if j >= args_len:
                return j
            a = sys.argv[j]
        return j
    elif t == BOOL:
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
    elif t == STRING_LIST:
        print("STRING_LIST")
        i += 1
        while i < args_len and i != "--":
            print("append", t, sys.argv[i])
            params.append(get_arg(i, "missing argument"))
            i += 1
        return i
    else:
        exit("unknow arguments: " + param_name)
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
                    if i < args_len:
                        ca = sys.argv[i]
                    else:
                        ca = None

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
