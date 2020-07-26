# 循环遍历文件夹里的文件
import sys
sys.path.append('..')  # append the main directory path
"""customise the filepath in readindex_no_pos.py"""
import os
import parse
def walkFile(file):
    for root, dirs, files in os.walk(file):
        # root 表示当前正在访问的文件夹路径
        # dirs 表示该文件夹下的子目录名list
        # files 表示该文件夹下的文件list
        # 遍历文件
        for f in files:
            print('file_path', os.path.join(root, f))
            # 对文件的操作
            parse.openfile(os.path.join(root,f))



        # 遍历所有的文件夹
        for d in dirs:
            print('Dirs',os.path.join(root, d))

def readfiles():
    walkFile("pcap")

if __name__ == '__main__':
    readfiles()

