#!/usr/bin/env python
import pika
import json

def send(key, methode, args):
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    payload = json.dumps ({
        "method": methode,
        "params": args,
        "jsonrpc": "2.0",
        "id": 0,
    })

    channel.basic_publish(exchange='amq.direct',
                          routing_key=key,
                          body=payload)

    print(" [x] Sent 'msg!'")
    #rcv_queue = channel.queue_declare(queue='butterfly-res')

    connection.close()
