import pyshark
import struct
import subprocess
import json
import os
from datetime import datetime

PACKET_DIR_PATH = './packets/'

def append_json_to_file(data, path_file) -> bool:
    with open(path_file, 'ab+') as f:
        f.seek(0,2)
        if f.tell() == 0 :
            f.write(json.dumps([data], ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
        else :
            f.seek(-1,2)
            f.truncate()
            f.write(','.encode('utf-8'))
            f.write(json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
            f.write(']'.encode('utf-8'))

def get_tcp_payloads():
    capture = pyshark.LiveCapture(interface='lo0', display_filter='mqtt')
    for packet in capture.sniff_continuously():
        payload_list = list(map(lambda x : '0x' + x, str(packet.tcp.payload).split(':')))
        timestamp = datetime.now().timestamp()
        file_name = PACKET_DIR_PATH + str(timestamp) + '_packet.bin'
        with open(file_name, 'wb') as f:
            for x in payload_list:
                f.write(struct.pack("B", int(x, 16)))
        executed_file_path = './mqttPacketParser.out'
        command = [executed_file_path, file_name]
        res = subprocess.check_output(command).decode('utf-8').split('\n')
        json_dict = {'timestamp': timestamp, 'mqtt_packet': list(payload_list)}
        for el in res[:len(res)-1]:
            splite_equal = el.rsplit('=', 1)
            if len(splite_equal) != 2:
                print('err_data:', res)
                print('split equal error.')
            else:
                dic_name = splite_equal[0]
                dic_value = splite_equal[1]
                json_dict[dic_name] = dic_value
        # json_string = json.dumps(json_dict, ensure_ascii=False)
        mqtt_packet_json_path = PACKET_DIR_PATH + 'mqtt_packet.json'
        append_json_to_file(json_dict, mqtt_packet_json_path)

if __name__ == "__main__":
    if not os.path.exists(PACKET_DIR_PATH):
        os.makedirs(PACKET_DIR_PATH)
    get_tcp_payloads()