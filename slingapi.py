import socket
import struct
import binascii
import sys
import select
import time
import shutil
import hashlib
import select
from threading import Thread, Event
from collections import deque

import requests
from Crypto.Cipher import AES
import m3u8
import aiohttp
import asyncio
import aiofiles

class SlingConnection:
    def __init__(self, ip, port, username, password):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.base_url = "http://{0}:{1}/".format(ip, port)

        self.session_id = 0
        self.sequence = 0
        self.data_buffer = b''
        self.control_client = 0
        self.key_mode = 0x2000
        self.tea_key = binascii.unhexlify("AAAADEBCBABBFB87FACFCC7CBCAADDDD")
        self.custom_headers = {"User-Agent": "spm-android-phone-freeapp/2.1.14"}
        self.session = self.create_session()
        self.base_playlist_url = ""
        self.playlist_url = ""
        self.start_time = 0
        self.segment_queue = deque()
        self.m3u8_uri = ""

        self.decyption_key = b""
        self.playlist = ""
        self.segments = {}
    
    def connect(self):
        self.control_client = self.sling_open_socket()
        self.send_receive_command(0x67, struct.pack("<L 32s 32s 128x L", 1, self.futf16(self.username), self.futf16(self.password), 1))

        challenge = binascii.unhexlify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.send_receive_command(0xc6, struct.pack("<L 16s 36x", 1, challenge))

        self.key_mode = 0x8000

        self.tea_key = self.xor_bytes(self.get_dynamic_key(challenge, self.session_id, 2, 3), self.get_dynamic_key(self.data_buffer[:16], self.session_id, -1, -4))

        self.send_command(0x03eb)
        self.send_command(0x81)
        self.send_command(0x76)
        self.send_command(0x03ef)
        self.receive_command()
        self.receive_command()
        self.receive_command()
        self.receive_command()

        self.send_command(0x03ed, struct.pack("<L 8x L", 2, 0))
        self.send_command(0x03ed, struct.pack("<L 8x L", 2, 1))
        self.send_command(0x86, struct.pack("<L 8x L 240x", 1, 0))
        
        start_time = time.time()
        self.start_time = start_time
        stopFlag = Event()
        thread = Updater(self, stopFlag, start_time)
        thread.start()

        self.receive_command()
        self.receive_command()
        self.receive_command()

        self.send_command(0x7e, struct.pack("<L L", 9, 0))
        self.receive_command()

        self.send_command(0xa6, struct.pack("10H 4x H 70x", 0x05cf, 0, 0x14, 0x08, 0x1f40, 0x60, 0x01, 0x1e, 0, 0xbd, 0x04))

        # video settings may be set in this command
        self.send_command(0xd5, struct.pack("8H 16x 11H 10x", 0xf, 0x0, 0x0201, 0x01, 0x05, 0x0, 0x09c6, 0x0642,
                    0x0103, 0x1e21, 0x0c, 0x0, 0x1770, 0x201e, 0x01, 0x0,
                    0x60, 0x20, 0x03))
        # alternate version. not sure of the difference
        # send_command(0xd5, struct.pack("8H 16x 12H 8x", 0xf, 0x0, 0x0201, 0x01, 0x05, 0x0, 0x09c6, 0x0642,
        # 			0x0103, 0x1e21, 0x0c, 0x0, 0x1770, 0x201e, 0x01, 0x0,
        # 			0x60, 0x20, 0x03, 0x0f03))

        self.receive_command()
        self.receive_command()
        self.receive_command()

        self.init_playlist_url()


    def send_receive_command(self, opcode, data):
        self.sequence += 1
        parity = 0
    
        if (opcode == 0x66):
            senddata = struct.pack("5H 6x 2H 4x H 6x", 0x201, self.session_id, opcode, 0, self.sequence, len(data), self.key_mode, parity)
            self.control_client.send(senddata)
            return

        if (self.key_mode == 0x8000):
            paritydata = struct.unpack("{}B".format(len(data)), data)
            for intdata in paritydata:
                parity ^= intdata

        if opcode == 0xc6:
            headercode = 0x201
        else:
            headercode = 0x101

        senddata = b''

        if(data):
            senddata = struct.pack("5H 6x 2H 4x H 6x", headercode, self.session_id, opcode, 0, self.sequence, len(data), self.key_mode, parity) + self.tea(data, self.tea_key, 1)
        else:
            senddata = struct.pack("5H 6x 2H 4x H 6x", headercode, self.session_id, opcode, 0, self.sequence, len(data), self.key_mode, parity)
        
        self.control_client.send(senddata)

        if (opcode == 0x66):
            return

        hbuf = self.control_client.recv(32)
        
        self.session_id, stat, dlen  = struct.unpack("2x H 8x H 2x H", hbuf[:18])

        if (dlen):
            data_buffer = self.control_client.recv(dlen)
            self.data_buffer = self.tea(data_buffer, self.tea_key, 0)
    
    def sling_open_socket(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((self.ip, self.port))

        initrequest = ("GET /stream.asf HTTP/1.1\r\nAccept: */*\r\n"
                    "Pragma: Sling-Connection-Type=Control, Session-Id={0}, PlayerInstance-Id=000000000000000, Client-Capability=1\r\n\r\n".format(self.session_id))

        client.send(initrequest.encode())
        return client

    def send_command(self, opcode, data=b""):
        self.sequence += 1
        headercode = 0x201
        parity = 0

        if (self.key_mode == 0x8000):
            paritydata = struct.unpack("{}B".format(len(data)), data)
            for intdata in paritydata:
                parity ^= intdata

        datapack = b""
        if data:
            datapack = self.tea(data, self.tea_key, 1)

        httppack = struct.pack("5H 6x 2H 4x H 6x", headercode, self.session_id, opcode, 0, self.sequence, len(data), self.key_mode, parity) + datapack

        bytessent = self.control_client.send(httppack)
    
    def receive_command(self, wait = False):
        hbuf = b''
        if wait:
            hbuf = self.control_client.recv(32, socket.MSG_WAITALL)
        else:
            hbuf = self.control_client.recv(32)
        
        stat = 0
        dlen = 0
        self.session_id, stat, dlen  = struct.unpack("2x H 8x H 2x H", hbuf[:18])

        if (dlen):
            self.data_buffer = self.control_client.recv(dlen)

            if (dlen != len(self.data_buffer)):
                sys.exit("missing or bad response data")

            self.data_buffer = self.tea(self.data_buffer, self.tea_key, 0)
    
    def send_keep_alive(self):
        self.send_receive_command(0x66, "")
    
    def send_remote_button(self, btncode):
        self.send_receive_command(0x87, struct.pack("2H 468x H x H 2x", btncode, 0xFA, 0x0201,0x0100))

    # adapted from https://stackoverflow.com/a/64283770
    async def download_all_segments(self, sess, dldict):
        tasks = []
        sem = asyncio.Semaphore(3)
        for fname, dlurl in dldict.items():
            tasks.append(
                asyncio.wait_for(
                    self.download_segment(dlurl, sess, sem, fname),
                    timeout=20,
                )
            )
        return await asyncio.gather(*tasks)

    async def download_segment(self, url, sess, sem, dest_file):
        async with sem:
            # don't download segments again
            if dest_file in self.segments:
                return

            content = b""
            segmentnumber = int(dest_file[7:-3])
            
            await asyncio.sleep(((segmentnumber % 3) + 1) * 0.06)

            async with sess.get(url) as res:
                content = await res.read()
            self.segments[dest_file] = content
            ready = select.select([self.control_client], [], [], 0)
            if ready[0]:
                self.receive_command()

            if len(content) < 1000:
                print("missed segment: {0}".format(dest_file))

    def init_playlist_url(self):
        response = requests.get("{0}{1}-0.m3u8".format(self.base_url, self.session_id), headers=self.custom_headers)
        playlistbase = m3u8.loads(response.text)
        videopath = playlistbase.playlists[0].uri.split("/")[1]
        self.base_playlist_url = "{0}{1}-0/{2}/".format(self.base_url, self.session_id, videopath)
        self.playlist_url = "{0}{1}".format(self.base_url, playlistbase.playlists[0].uri)

    async def update_segments(self):
        response = requests.get(self.playlist_url, headers=self.custom_headers)
        playlist = m3u8.loads(response.text)
        dldict = {}
        new_key = self.set_video_key(playlist.keys[0])
        for seg in playlist.segments:
            fullsegmenturl = "{0}{1}".format(self.base_playlist_url, seg.uri)
            dldict[seg.uri] = fullsegmenturl
            self.segment_queue.append(seg.uri)
            seg.uri = "segments/" + seg.uri
            seg.key = new_key
        await(self.download_all_segments(self.session, dldict))
        self.playlist = playlist.dumps()
    
    def set_video_key(self, m3u8key):
        m3u8_uri = m3u8key.uri[8:]
        if m3u8_uri != self.m3u8_uri:
            self.m3u8_uri = m3u8_uri
            password = self.password.encode('utf-8')
            # salt for getting key is 16 bytes not 32
            salt = binascii.unhexlify(m3u8key.iv[2:18]) 

            key = SlingConnection.get_key(password, salt)
            iv = SlingConnection.get_iv(password, salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(binascii.unhexlify(m3u8_uri))

            self.decyption_key = decrypted[:16]

        return m3u8.Key("AES-128", "/key.bin", "/key.bin", iv=m3u8key.iv)

    @staticmethod
    def create_session():
        return aiohttp.ClientSession()

    @staticmethod
    def tea(buf, key, enc):
        keys = struct.unpack("<{}L".format(len(key)//4), key)
        longs = struct.unpack("<{}L".format(len(buf)//4), buf)
        longs = list(longs)
        sub = 0
        if (enc == 1):
            sub = SlingConnection.tea_encrypt
        else:
            sub = SlingConnection.tea_decrypt

        for j in range(0, len(longs), 2):
            longs[j], longs[j+1] = sub(longs[j], longs[j+1], keys)
        
        return struct.pack("<{}L".format(len(longs)), *longs)
    
    @staticmethod
    def tea_encrypt(v0, v1, k):
        sum = 0
        delta = 0x9E3779B9
        k0 = k[0]
        k1 = k[1]
        k2 = k[2]
        k3 = k[3]
        for i in range(32):
            sum += delta
            v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
            v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        return v0, v1
    
    @staticmethod
    def tea_decrypt(v0, v1, k):
        sum = 0xC6EF3720
        delta = 0x9E3779B9
        k0 = k[0]
        k1 = k[1]
        k2 = k[2]
        k3 = k[3]
        for i in range(32):
            v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
            v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
            sum -= delta
        return v0, v1
    
    @staticmethod
    def get_dynamic_key(*args):
        t = bytes(SlingConnection.bit_string(args[0]).encode())
        s = bytes(SlingConnection.bit_string(struct.pack("H", args[1])).encode())
        v = 0
        r = 0

        for i in range(1,17):
            r = i * args[(args[1] >> i - 1 & 1) + 2]
            
            t = t[r:] + t[0:r]

            t = SlingConnection.xor_bytes(t, s)
            
            if (i == 1):
                v = t
            else:
                v = SlingConnection.xor_bytes(v,t)
        
        return SlingConnection.bit_string_pack(v)
    
    @staticmethod
    def xor_bytes(b1, b2):
        if (len(b1) > len(b2)):
            padding = "0" * (len(b1) - len(b2))
            b2 += bytes(padding, encoding="utf-8")

        result = bytearray()
        for b1, b2 in zip(b1, b2):
            result.append(b1 ^ b2)

        return bytes(result)
    
    @staticmethod
    def bit_string(bytesvar):
        output = ""
        for byte in bytesvar:
            output += format(byte, '08b')[::-1]
        return output
    
    @staticmethod
    def bit_string_pack(bytesvar):
        string = bytesvar.hex()
        bit_string = string[1::2]
        output = b""
        for i in range(len(bit_string) // 8):
            start = i*8
            end = start+8
            byte = int(bit_string[start:end][::-1], 2)
            byte = bytes([byte])
            output += byte
        return output

    @staticmethod
    def futf16(string):
        string = bytes(string, "utf-8")
        unpacked = struct.unpack("{}B".format(len(string)), string)
        packed = struct.pack("{}H".format(len(string)), *unpacked)
        return packed

    @staticmethod
    def get_key(password, salt):
        derivedkey = hashlib.pbkdf2_hmac('sha1', password, salt, 1313, 48)
        return derivedkey[:16]
    
    @staticmethod
    def get_iv(password, salt):
        fullhash =  b''
        previous = b''
        
        while len(fullhash) < 32:
            hashed = hashlib.sha1(previous + password + salt).digest()
            for i in range(1110):
                hashed = hashlib.sha1(hashed).digest()
            previous = hashed
            fullhash += hashed

        return fullhash[16:32]

# adapted from https://stackoverflow.com/a/12435256
class Updater(Thread):
    def __init__(self, inst, event, start_time):
        Thread.__init__(self)
        self.inst = inst
        self.stopped = event
        self.start_time = start_time

    def run(self):
        while not self.stopped.wait(10):
            self.inst.send_keep_alive()
            while len(self.inst.segment_queue) > 30:
                # don't want segments in memory forever
                self.inst.segments.pop(self.inst.segment_queue.popleft())