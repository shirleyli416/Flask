# html用
from flask import Flask, render_template, request, send_from_directory
import json
app = Flask(__name__)

@app.route('/')
def Home():
    return render_template('index.html')

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/about')
def about():
    return render_template('about.html')



@app.route('/result',methods=['GET'])
def result():
    mode = request.args.get('mode')
    print(mode)
    dictPutall = json.load(open('json/dictAllPut.json','r'))
    dictpcap = {}
    if mode  == 'pcap1':
        dictpcap = dictPutall['pcap1']
    elif mode == 'pcap2':
        dictpcap = dictPutall['pcap2']
    elif mode == 'pcap3':
        dictpcap = dictPutall['pcap3']
    elif mode == 'pcap4':
        dictpcap = dictPutall['pcap4']
    elif mode == 'pcap5':
        dictpcap = dictPutall['pcap5']
    elif mode == 'pcap6':
        dictpcap = dictPutall['pcap6']
    elif mode == 'pcap7':
        dictpcap = dictPutall['pcap7']
    elif mode == 'pcap8':
        dictpcap = dictPutall['pcap8']

    return render_template('result.html',dictPutall=dictpcap)
