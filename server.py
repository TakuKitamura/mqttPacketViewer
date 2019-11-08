from bottle import run, route, response, template
import time
import shutil
import os
import pyshark
import struct
import atexit
import subprocess
import json
# from datetime import datetime
packts_dir_path = './packets/'
def get_tcp_payloads():
    id = 1
    capture = pyshark.LiveCapture(interface='lo0', display_filter='mqtt')
    capture.sniff(timeout=0)
    for packet in capture.sniff_continuously():
        # print(1)
        payload_list = str(packet.tcp.payload).split(':')
        # id = str(datetime.now().timestamp())
        file_name = packts_dir_path + str(id) + '_packet.bin'
        with open(file_name, 'wb') as f:
            for x in payload_list:
                f.write(struct.pack("B", int(x, 16)))
        executed_file_path = './mqttPacketParser.out'
        command = [executed_file_path, file_name]
        # print(command)
        res = subprocess.check_output(command).decode('utf-8').split('\n')
        json_dict = {'id': id, 'mqtt_packet': list(payload_list)}
        for el in res[:len(res)-1]:
            # print()
            splite_equal = el.rsplit('=', 1)
            # print(splite_equal)
            if len(splite_equal) != 2:
                print('err_data:', res)
                print('split equal error.')
            else:
                dic_name = splite_equal[0]
                dic_value = splite_equal[1]
                json_dict[dic_name] = dic_value
        json_string = json.dumps(json_dict, ensure_ascii=False)
        yield '{}\n\n'.format(json_string)
        id += 1

@route('/')
def index():
    return template('index.html')

@route('/payload')
def sse():
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Content_Type']  = 'text/event-stream'
    # while (True):
    # id = 1
    tcp_payloads = get_tcp_payloads()
    # print(1)
    for payload in tcp_payloads:
        # print(1)
        yield 'data:{}\n\n'.format(payload)
def when_exit():
    shutil.rmtree(packts_dir_path)

atexit.register(when_exit)
os.mkdir(packts_dir_path)
run(host='localhost', port=3000, debug=False, reloader=False)