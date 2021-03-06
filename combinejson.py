# 将处理好的文件组合成一个字典
# import scapy.all as scapy
from scapy.all import *
from scapy.layers.inet import IP, TCP
import pymysql
import json
import re

def filter(pkt):
    '''
    packet.payload: IP layer
    packet.payload.payload: TCP layer
    packet.payload.payload.payload: RAW layer
    '''

    result_dict = {}

    i = 0
    while i < len(pkt):
        # print('No  ', i )
        # packets[i].show()
        '''保存三次握手的数据包到dictno'''
        if i < len(pkt) - 5 and pkt[i].haslayer(TCP) and pkt[i + 1].haslayer(TCP) and pkt[i + 2].haslayer(TCP) and pkt[i +3].haslayer(TCP) and pkt[i + 4].haslayer(TCP) and pkt[i +5].haslayer(TCP):
            if pkt[i + 1][TCP].ack == pkt[i][TCP].seq + 1 and pkt[i + 2][TCP].ack == pkt[i + 1][TCP].seq + 1:
                striseq = 'SEQ=' + str(pkt[i][TCP].seq) + ' ACK=' + str(pkt[i][TCP].ack)
                stri1seq = 'SEQ=' + str(pkt[i + 1][TCP].seq) + ' ACK=' + str(pkt[i + 1][TCP].ack)
                stri2seq = 'SEQ=' + str(pkt[i + 2][TCP].seq) + ' ACK=' + str(pkt[i + 2][TCP].ack)
                transi = 'Phone sends a request to IoT device (Bulb) to establish a connection (Send SYN)'
                transi1 = 'Receiving the request, Bulb knows that it could successfully establish a connection with the phone. And Send a message to phone, indicating that I have received your request and we could establish a connection(Send ACK=SYN+1 and SYN).'
                transi2 = 'Phone received the message from the Bulb and replied that we had successfully established the connection (ACK = SYN+1).'
                listsi = [striseq,transi,'L']
                listsi1 = [stri1seq,transi1 , 'R']
                listsi2 = [stri2seq, transi2, 'L']
                result_dict.update({i: listsi})
                result_dict.update({i + 1: listsi1})
                result_dict.update({i + 2: listsi2})
                print('TCP ..........................三次握手', i+1)
                # print(dictno)

                '''保存 PUT GET 数据包 到dictrequest'''
            if pkt[i+3].haslayer(Raw):
                byte2str = bytes.decode(pkt[i+3][Raw].load)
                '''type = string'''
                    # byte2str = re.sub(r'\r\n', '<br>', byte2str)
                    # dicthasload.update({i: byte2str})

                if byte2str[0:3] == 'GET':
                    transGet = 'This is a Request message from Phone. The message means phone want to know current status of bulb?'
                    listGet = [byte2str, transGet, 'L']
                    result_dict.update({i+3: listGet})
                if byte2str[0:3] == 'PUT':
                    transPut = 'This is a Request message from Phone. The message means Phone will push data to Bulb and please ready to update status.'
                    listPut = [byte2str, transPut, 'L']
                    result_dict.update({i+3: listPut})

            if pkt[i + 4].haslayer(Raw) and bytes.decode(pkt[i + 4][Raw].load)[0:4] =='HTTP':
                        # print('Flag------------------',pkt[i+1][TCP].flags)
                        # print('http---------', bytes.decode(pkt[i+1][Raw].load))
                byte2str = bytes.decode(pkt[i + 4][Raw].load)

                HttpTrans = 'This is a response message. The request Phone sent was handled normally.'
                listHttp = [byte2str,HttpTrans,'R']
                result_dict.update({i + 4: listHttp})

                if pkt[i + 5].haslayer(Raw) and pkt[i + 6].haslayer(Raw) and pkt[i + 5][TCP].flags == 'PA' and pkt[i+6][TCP].flags =='FPA':
                    newstr = bytes.decode(pkt[i + 5][Raw].load) + bytes.decode(pkt[i + 6][Raw].load)
                    transinfo = 'test test'
                    strinfo = newstr.split('application/json', 1)

                    if 'on":false' in strinfo[1]:
                        transinfo = 'The light is off'
                    elif 'on":true' in strinfo[1]:
                        if '"bri"' in strinfo[1]:
                            result = re.findall(r'".*bri":(\d+),".*',strinfo[1])
                            transinfo = 'The light is on and the bright is '+result[0]
                    listinfo = [strinfo[1], transinfo, 'L']
                    result_dict.update({i + 5: listinfo})

                elif pkt[i + 5].haslayer(Raw) and pkt[i + 5][TCP].flags == 'FPA':
                    newstr = bytes.decode(pkt[i + 5][Raw].load)
                    transinfo = 'User Turn on the light'
                    strinfo = newstr.split('application/json', 1)
                    if 'on\":false' in strinfo[1]:
                        transinfo = 'The light is off'
                    elif 'on\":true' in strinfo[1]:
                        if '"bri"' in strinfo[1]:
                            result = re.findall(r'".*bri":(\d+),".*',strinfo[1])
                            transinfo = 'The light is on and the bright is '+result[0]
                    elif 'success' in strinfo[1] and 'true' in strinfo[1]:
                        transinfo = 'User Turn on the light'
                    elif 'success' in strinfo[1] and 'state/on":true}' in strinfo[1]:
                        transinfo = 'User Turn on the light'

                    elif 'success' in strinfo[1] and 'false' in strinfo[1]:
                        transinfo = 'User Turn off the light'
                    elif 'success' in strinfo[1] and 'bri":' in strinfo[1]:
                        result = re.findall(r'".*bri":(\d+)}}.*', strinfo[1])
                        transinfo = 'User Change the bright to  ' + result[0]
                    elif 'success' in strinfo[1] and 'TcqOY6HeeWmJX5F' in strinfo[1]:
                        transinfo = 'User Change the Bulb scene to Light Night'
                    elif 'success' in strinfo[1] and 'uNkI514cZW21Rsj' in strinfo[1]:
                        transinfo = 'User Change the Bulb scene to Bright'
                    elif 'success' in strinfo[1] and 'TcqOY6HeeWmJX5F' in strinfo[1]:
                        transinfo = 'User Change the Bulb scene to Fading'

                    listinfo = [strinfo[1], transinfo, 'L']
                    result_dict.update({i + 5: listinfo})
                else:
                    result_dict.update({i + 5: []})

        i += 1

    return result_dict

def dict_chunk(dicts,size):
    new_list = []
    dict_len = len(dicts)
    # 获取分组数
    while_count = dict_len // size + 1 if dict_len % size != 0 else dict_len / size
    split_start = 0
    split_end = size
    while(while_count > 0):
        # 把字典的键放到列表中，然后根据偏移量拆分字典
        new_list.append({k: dicts[k] for k in list(dicts.keys())[split_start:split_end]})
        split_start += size
        split_end += size
        while_count -= 1
    return new_list



def openfile(filename):
    packets = scapy.all.rdpcap(filename)
    filter(packets)

def jsonwrite(dict):
    # dict_pkt = filter(pkt)
    filename = 'json/dictAllPut.json'
    with open(filename, 'w') as file_obj:
        json.dump(dict, file_obj, indent = 4 ,sort_keys=True)

def get_data():
    with open('json/json1.json', 'r') as f:
        packet_text = json.load(f)  # 解析每一行数据
    return packet_text

if __name__ == '__main__':
    '''test'''
    # packets = scapy.all.rdpcap("pcap/test8.pcap")
    # # jsonwrite(packets)
    # filter(packets)
    # res = dict_chunk(filter(packets), 6)
    # print(res)
    # print(res[1])

    # packets1 = scapy.all.rdpcap("pcap/test1.pcap")

    dict1 = filter(scapy.all.rdpcap("pcap/test1.pcap"))
    print(dict1)
    dict2 = filter(scapy.all.rdpcap("pcap/test2.pcap"))
    dict3 = filter(scapy.all.rdpcap("pcap/test3.pcap"))
    dict4 = filter(scapy.all.rdpcap("pcap/test4.pcap"))
    dict5 = filter(scapy.all.rdpcap("pcap/test5.pcap"))
    dict6 = filter(scapy.all.rdpcap("pcap/test6.pcap"))
    dict7 = filter(scapy.all.rdpcap("pcap/test7.pcap"))
    dict8 = filter(scapy.all.rdpcap("pcap/test8.pcap"))
    dictAllPut = {"pcap1":dict1,"pcap2":dict2,"pcap3":dict3,"pcap4":dict4,"pcap5":dict5,"pcap6":dict6,"pcap7":dict7,"pcap8":dict8}
    print(dictAllPut)
    jsonwrite(dictAllPut)

    # jsonwrite(packets)
    # filter(packets)
    # print(packets[27][Raw].load)
    # print(packets[28].payload.payload.payload)
    # packets[395].show()
    # packets[99].show()
    # packets[108].show()
    # packets[119].show()
    # packets[129].show()
    # filter(packets)