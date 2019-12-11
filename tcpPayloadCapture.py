# import pyshark
import struct
import subprocess
import json
import os
from datetime import datetime
from scapy.all import *

PACKET_DIR_PATH = './packets/'

stored_mqtt_packet_data = ''

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

def get_tcp_payloads(packet):
    if type(packet.payload.payload.payload) is scapy.packet.Raw:
        mqtt_packet_data = bytes(packet.payload.payload.payload).hex()
        flags_str = str(packet.payload.payload.flags)
        global stored_mqtt_packet_data
        if 'P' in flags_str:
            stored_mqtt_packet_data += mqtt_packet_data
            payload_list = ['0x' + stored_mqtt_packet_data[i: i+2]
                for i in range(0, len(str(stored_mqtt_packet_data)), 2)]
            stored_mqtt_packet_data = ''
            timestamp = datetime.now().timestamp()
            file_name = PACKET_DIR_PATH + str(timestamp) + '_packet.bin'
            with open(file_name, 'wb') as f:
                for x in payload_list:
                    f.write(struct.pack("B", int(x, 16)))
            executed_file_path = './mqttPacketParser.out'
            command = [executed_file_path, file_name]
            res = subprocess.check_output(command).decode('utf-8', 'ignore').split('\n')
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
        else:
            stored_mqtt_packet_data += mqtt_packet_data
            return

if __name__ == "__main__":
    if not os.path.exists(PACKET_DIR_PATH):
        os.makedirs(PACKET_DIR_PATH)
    sniff(iface='lo0', prn=get_tcp_payloads, filter="tcp port 1883")