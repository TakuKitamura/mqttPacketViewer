from bottle import run, route, response, template
import time
import os
import subprocess
import json

PACKET_DIR_PATH = './packets/'

@route('/')
def index():
    return template('index.html')

@route('/payload')
def sse():
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Content_Type']  = 'text/event-stream'
    mqtt_packet_json_path = PACKET_DIR_PATH + 'mqtt_packet.json'
    if (os.path.isfile(mqtt_packet_json_path)):
        with open(mqtt_packet_json_path) as f:
            yield 'data:{}\n\nretry:{}\n\n'.format(f.read(), 2000)
    else:
        yield 'data:{}\n\nretry:{}\n\n'.format('mqtt_packet_json is not found.', 2000)
    # while (True):
    # id = 1
    # tcp_payloads = get_tcp_payloads()
    # # print(1)
    # for payload in tcp_payloads:
    #     # print(1)
    #     yield 'data:{}\n\n'.format(payload)
run(host='localhost', port=3000, debug=False, reloader=False)