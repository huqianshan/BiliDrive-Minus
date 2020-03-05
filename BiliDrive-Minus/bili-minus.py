import hashlib
import inspect
import json
import math
import os
import re
import sys
import threading
import time
import types
from io import BytesIO

import requests
from PIL import Image

from bilibili import Bilibili


"""
1. reduce data redundancy
2. simplify the procedure
3. easy for change
"""

"""
策略与规则的分离：
    1, 什么是策略，什么是规则。
    2. 各自的范围
"""


def log(message):
    local_time = time.localtime(time.time())
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S', local_time)}] {message}")


def warn(e: Exception):
    # Get the previous frame in the stack, otherwise it would be this function!!!
    func = inspect.currentframe().f_back.f_code
    print("Error:[%s]; function:[%s] in file [%s]: line [%i]" % (
        e, func.co_name,
        os.path.basename(func.co_filename), func.co_firstlineno))


def size_string(byte):
    if byte >= 1024 * 1024 * 1024:
        tem = f"{byte/1024 / 1024 / 1024:.2f} GB"
    elif byte >= 1024*1024:
        tem = f"{byte / 1024 / 1024:.2f} MB"
    elif byte >= 1024:
        tem = f"{byte / 1024:.2f} KB"
    else:
        tem = f"{int(byte)} B"
    return tem


bundle_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))


def meta_string(url): return ("bdrive://" + re.findall(r"[a-fA-F0-9]{40}", url)[0]) if re.match(r"^http(s?)://i0.hdslb.com/bfs/album/[a-fA-F0-9]{40}.[\S]*", url) else url


def calc_sha1(data, hexdigest=False):
    try:
        sha1 = hashlib.sha1()
        if isinstance(data, types.GeneratorType):
            for chunk in data: #data may be NoneType
                sha1.update(chunk)
        else:
            sha1.update(data)
        return sha1.hexdigest() if hexdigest else sha1.digest()
    except Exception as e:
        warn(e)
        return None
 


def file_name_check(file_name):
    if not os.path.exists(file_name):
        log(f"文件{file_name}不存在")
        return 1
    if os.path.isdir(file_name):
        log("暂不支持上传文件夹")
        return 2
    log(f"上传: {os.path.basename(file_name)} ({size_string(os.path.getsize(file_name))})")
    return None


def read_in_chunk(file_name, chunk_size= 16 * 1024 * 1024, chunk_number=-1):
    chunk_counter = 0
    with open(file_name, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if data != b"" and(
                    chunk_number == -1 or chunk_counter < chunk_number):
                yield data
                chunk_counter += 1
            else:
                return


def read_history(json_name="history.json"):
    try:
        with open(os.path.join(bundle_dir, json_name), "r", encoding="utf-8") as f:
            history = json.loads(f.read())
    except Exception as e:
        warn(e)
        history = {}
    return history


def url_from_sha1(sha1, img_format="png"):
    img_format = img_format.lower()
    if img_format not in ['png', 'jpg', 'x-ms-bmp']:
        log(f"链接指定图片格式不对，应为png,jpg,x-ms-bmp之一，而非{img_format}")
        return None
    return f"http://i0.hdslb.com/bfs/album/{str(sha1)}."+img_format

class Args(object):
    """
    args.threads:    threads number \n
    args.block_size: block size in mb \n
    args.file:       upload file's name \n
    args.format:     png,jpg; \n
    """
    def __init__(self,file=None,threads=8,block_size=16,img_format="png",mode="RGB"):
        self.file=file
        self.threads=threads
        self.block_size=block_size*1024*1024
        self.img_format=img_format
        self.mode=mode

class UArgs(Args):
    """
    args.username:   bili username \n
    args.password:   password.
    """
    def __init__(self, file_name,user,passwd):
        super().__init__(file=file_name)
        self.file = file_name
        self.username = user
        self.password = passwd


class DArgs(Args):
    """
    args.link:     
    args.force:    overwrite
    """
    def __init__(self, link,force=False,file=None):
        super().__init__(file)
        self.link = link
        self.force=force


class ImageConverter(object):

    def __init__(self,args:Args):
        self.img_format = args.img_format
        # self.dict = {"PNG": "png", "BMP": "x-ms-bmp","JPEG": "jpg"}  # Todo Bug
        self.mode = args.mode

    def _image_pack(self, file_data):
        """
        add sha1 to data
        """
        sha1 = calc_sha1(file_data)
        merged_data = file_data+sha1+b"\xff"
        return merged_data
    
    
    def _image_unpack(self, packed_data):
        if packed_data[-1] ==255: # type(bytes[-1])==int ==> 255=b'\xff'
            data, raw_sha1 = packed_data[:-(1+20)], packed_data[-(1+20):-1] # sha1_length=20
            new_sha1 = calc_sha1(data)
            if new_sha1 == raw_sha1:
                return data
            else:
                raise ValueError(f"图片中存储sha1：{raw_sha1},而图中数据计算得到sha1: {new_sha1}")
        raise ValueError(f"下载图片于既定格式不符，无法复原数据")

    def image_encode(self, file_data):
        """
        read binary file_data, converting to image data by PIL\n\n
        imagedata = imgheader + file_data + sha1 + b  xff + {b x00} *n

        :file_data: raw pixel data not include image header in binary\n
        :format: the image format like "PNG"(default),"JPEG","GIF".\n
        :mode: image mode like "RGB" "L" "P" \n
        :return: full_image_data (binary) else None if something failed\n
        """
        length = len(file_data)
        file_data = self._image_pack(file_data)
        if self.mode.upper() == "RGB":
            "3x8-bit pixels, true color"
            base = 3  # [r,g,b]
        elif self.mode.upper() in ["L", "P"]:
            "8-bit pixels, black and white"
            base = 1
        else:
            log(f"需指定图像mode为以下模式之一，RGB,L,P")
            return None

        pixel_number = math.ceil(length / base)
        width = math.ceil(math.sqrt(pixel_number))
        height = math.ceil(pixel_number / width)

        pixel_data = file_data+b'\x00'*(width*height*base-length)
        try:
            image = Image.frombytes(self.mode, (width, height), bytes(pixel_data))
            img_fp = BytesIO()
            image.save(img_fp, format=self.img_format)
            # full_image_data is header of image plus pixel data (pixel_data)
            full_image_data = img_fp.getvalue()            
        except Exception as e:
            warn(e)
            return None
        return full_image_data

    def image_decode(self, data):
        "get raw binary data from image binary data."
        try:
            if self.img_format.lower()== 'png':
                image = Image.open(BytesIO(data))
                pixel_data = image.tobytes()
                merged_data = pixel_data.rstrip(b"\x00")
                raw_data = self._image_unpack(merged_data)
            elif self.img_format.lower()=='x-ms-bmp':
                raw_data=data[62:]
            else:
                log(f"尚未支持此图片格式{self.img_format}解码")
                raw_data= None
            return raw_data
        except Exception as e:
            warn(e)
            return None
    


class CheckDuplicate(object):
    @staticmethod
    def check_duplicate(file_name,json_name=None):
        first_4mb_sha1 = calc_sha1(read_in_chunk(file_name, chunk_size=4 * 1024 * 1024,
         chunk_number=1), hexdigest=True)
        history = read_history() if not json_name else read_history(json_name)
        if first_4mb_sha1 in history:
            url = history[first_4mb_sha1]['url']
            loc_time = time.localtime(history[first_4mb_sha1]['time'])
            log(f"文件已于{time.strftime('%Y-%m-%d %H:%M:%S',loc_time)}上传, \
                 共有{len(history[first_4mb_sha1]['block'])}个分块")
            log(f"META URL -> {meta_string(url)}")
            return url
        else:
            return None

    @staticmethod
    def sha1_skippable(sha1, img_format="png"):
        url = url_from_sha1(sha1, img_format)
        headers = {
            'Referer': "http://t.bilibili.com/",
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
        }
        for _ in range(5):
            try:
                response = requests.head(url, headers=headers, timeout=10)
                return url if response.status_code == 200 else None
            except Exception as e:
                warn(e)
        return None

    @staticmethod
    def is_overwritable(file_name, force):
        if not force:
            return (input(f"文件{file_name}已存在, 是否覆盖? [y/N] ") in ["y", "Y"])
        else:
            return True  # force to overwrite

#Todo
#继承dict,使得Block可以通过获取属性值的方式去获取字典的键值
class ObjectDict(dict):
    def __init__(self, *args, **kwargs):
        super(ObjectDict, self).__init__(*args, **kwargs)

    def __getattr__(self, name):
        value = self[name]
        if isinstance(value, dict):
            value = ObjectDict(value)
        return value

#todo
class Block(object):
    """
    block_dict: 分块信息：url,size,sha1
    meta_dict: 文件记录信息，上传时间time,上传文件名filename,文件大小size,分块信息block_dict.
    """

    def __init__(self):
        self.block_dict = {}
        self.meta_dict = {}

    def add_block(self, index, url, size, sha1):
        self.block_dict[index] = {
            'url': url,
            'size': size,
            'sha1':  sha1,
        }

    def make_meta_dict(self, file_name):
        sha1 = calc_sha1(read_in_chunk(file_name), hexdigest=True)
        self.meta_dict = {
                'time': int(time.time()),
                'filename': os.path.basename(file_name),
                'size': os.path.getsize(file_name),
                'sha1': sha1,
                'block': [self.block_dict[i] for i in range(len(self.block_dict))],
        }
        return self.meta_dict

    def get_data(self, file_name):
        "specify upload filename ; \n return meta info in json"
        try:
            if not self.meta_dict:
                self.meta_dict = self.make_meta_dict(file_name)
            return json.dumps(self.meta_dict, ensure_ascii=False).encode("utf-8")
        except Exception as e:
            warn(e)
            return None

    def save(self, file_name, url, duplicate_key=None):
        "duplicate_key 存储每一个文件元数据的键值，默认为first_4mb_file"
        if not duplicate_key:
            first_4mb_sha1 = calc_sha1(read_in_chunk(file_name, chunk_size=4 * 1024 *1024, chunk_number=1),hexdigest=True)
        # todo mkdir for json
        # json_name = "history-"+os.path.basename(file_name)+".json"
        json_name = "history.json"
        history = read_history(json_name=json_name)
        self.meta_dict['url'] = url
        history[first_4mb_sha1] = self.meta_dict
        with open(os.path.join(bundle_dir, json_name), "w+", encoding="utf-8") as f:
            f.write(json.dumps(history, ensure_ascii=False, indent=2))
            log("日志记录成功")
        return True

class UploadClass(object):

    def __init__(self, args:UArgs):
        self.args = args

        self.done_flag = threading.Semaphore(0)
        self.terminate_flag = threading.Event()
        self.thread_pool = []
        self.cookies = None
        self.start_time = None
        self.block_num = 0

        self.block = Block()

    def login_check(self):
        try:
            with open(os.path.join(bundle_dir, "cookies.json"), "r", encoding="utf-8") as f:
                self.cookies = json.loads(f.read())
            return True
        except Exception as e:
            warn(e)
            log("Cookies加载失败, 请先登录")
            return False

    def login_handle(self, username=None, password=None):
        bilibili = Bilibili()
        if username and password:
            uname=username
            pword=password
        else:
            uname=self.args.username
            pword=self.args.password
        if bilibili.login(username=uname,password=pword):
            bilibili.get_user_info()
            self.cookies = bilibili.get_cookies()
            with open(os.path.join(bundle_dir, "cookies.json"), "w", encoding="utf-8") as f:
                f.write(json.dumps(self.cookies, ensure_ascii=False, indent=2))

    def file_upload(self):
        file_name = self.args.file
        block_size = self.args.block_size
        thread_num = self.args.threads
        log(f"线程数: {self.args.threads}")

        self.block_num = math.ceil(os.path.getsize(file_name) / (block_size))
        self.start_time = time.time()
        for index, block in enumerate(read_in_chunk(file_name, chunk_size=block_size)):
            if len(self.thread_pool) >= thread_num:
                self.done_flag.acquire()
            if not self.terminate_flag.is_set():
                # call core function
                self.thread_pool.append(threading.Thread(target=self._content_upload, args=(index, block)))
                self.thread_pool[-1].start()
            else:
                log("已终止上传, 等待线程回收")
                break
        for thread in self.thread_pool:
            thread.join()
        if self.terminate_flag.is_set():
            return None

    def _content_upload(self, index, block):
        try:
            img = ImageConverter(self.args)
            block_sha1 = calc_sha1(block, hexdigest=True)
            full_block = img.image_encode(block)
            full_block_sha1 = calc_sha1(full_block, hexdigest=True)
            # if url of its sha1 exists,then skipping upload just record
            url = CheckDuplicate.sha1_skippable(full_block_sha1)
            if url:
                log(f"分块{index + 1}/{self.block_num}上传完毕")
                self.block.add_block(index, url, len(block), block_sha1)
                self.done_flag.release()
                return
            for i in range(5):
                if self.terminate_flag.is_set():
                    return
                response = self._commit_upload(full_block)
                if response and response['code'] == 0:
                    url = response['data']['image_url']
                    log(f"分块{index + 1}/{self.block_num}上传完毕")
                    self.block.add_block(index, url, len(block), block_sha1)
                    self.done_flag.release()
                    return
                else:
                    # indicates some errors in uploading
                    self._parse_response(response, index, i)
                    self.terminate_flag.set()
        except Exception as e:
            self.terminate_flag.set()
            warn(e)

    def _parse_response(self, response, index, i):
        # Todo: should return response code
        log(f"分块{index + 1}/{self.block_num}第{i + 1}次上传失败")
        if not response:
            log("返回值为空，与远程连接断开")
        log(f"返回码code{response['code']},{response['message']}")
        return

    def _meta_upload(self):
        block_meta_json = self.block.get_data(self.args.file)

        img = ImageConverter(self.args)
        block_meta_img = img.image_encode(block_meta_json)
        for i in range(5):
            response = self._commit_upload(block_meta_img)
            if response and response['code'] == 0:
                url = response['data']['image_url']
                log("元数据上传完毕")
                meta_dict = self.block.meta_dict
                log(f"{meta_dict['filename']} ({size_string(meta_dict['size'])}) 上传完毕,\
                     用时{time.time() - self.start_time:.1f}秒,  \
                     平均速度{size_string(meta_dict['size'] / (time.time() - self.start_time))}/s")
                log(f"META URL -> {meta_string(url)}")
                self.block.save(self.args.file, url)
                return url
            else:
                self._parse_response(response, 0, i)
                log(f"元数据第{i + 1}次上传失败")
                return None
    
    def _commit_upload(self, data):
        api = "https://api.vc.bilibili.com/api/v1/drawImage/upload"
        headers = {
            'Origin': "https://t.bilibili.com",
            'Referer': "https://t.bilibili.com/",
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
        }
        payload = {
            'biz': "draw",
            'category': "daily",
        }
        
        files={
            "https://github.com/Hsury/BiliDrive/blob/a00799051d801b639910752b2347042e0e24d60e/BiliDrive/__main__.py#L78"
            }
        try:
            response = requests.post(
                api,
                headers=headers,
                cookies=self.cookies,
                data=payload,
                files=files,
                timeout=300).json()
            return response
        except Exception as e:
            warn(e)
            response = None
        
    def run(self):
        if not self.login_check():
            self.login_handle()
        self.file_upload()
        self._meta_upload()


class DownloadClass(object):

    def __init__(self, args:DArgs):
        self.args = args
        self.start_time = None
        self.meta_dict = None
        self.block_list = []

        self.done_flag = threading.Semaphore(0)
        self.terminate_flag = threading.Event()
        self.file_lock = threading.Lock()
        self.thread_pool = []
        self.fp = None

    def probe_meta(self):
        "return true if get info meta and file name"
        self.start_time = time.time()
        self.meta_dict = self._download_meta(self.args.link)

        if self.meta_dict:
            self.args.file = self.args.file if self.args.file else self.meta_dict['filename']
            log(f"开始下载: {os.path.basename(self.args.file)}({size_string(self.meta_dict['size'])}),\
                共有{len(self.meta_dict['block'])}个分块, 上传于{time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(self.meta_dict['time']))}")
        else:
            log("元数据解析失败")
        return self.meta_dict != None
    
    def __get_format(self,link):
        "auto select image-format"
        mode_full = re.match(r"^bdrive://[a-fA-F0-9]{40}$", link)
        mode_hash = re.match(r"^[a-fA-F0-9]{40}$", link)
        full_meta=None
        if mode_full or mode_hash:   
            suffix=re.findall(r"[a-fA-F0-9]{40}", link)[0]
            for mode in ['png', 'jpg', 'x-ms-bmp']:
                url = url_from_sha1(suffix, img_format=mode)
                status_code= self._request(url,probe_mode=True)
                if status_code==200:
                    self.args.img_format=mode
                    full_meta=self._commit_download(url)          
        elif link.startswith("http://") or link.startswith("https://"):
            full_meta = self._commit_download(link)
            self.args.img_format=link.rsplit('.')[-1]
        else:
            log(f"解析链接失败：link:{link}")
        return full_meta 


    def _download_meta(self, link):
        full_meta=self.__get_format(link)
        try:
            return json.loads(full_meta.decode("utf-8"))
        except Exception as e:
            warn(e)
            return None

    def resist_check(self):
        log(f"线程数: {self.args.threads}")
        if not self.args.file:
            self.probe_meta()
        file_name = self.args.file
        force = self.args.force if not self.args.force else None
        if not os.path.exists(file_name):
            self.block_list = list(range(len(self.meta_dict['block'])))
            return True
        elif os.path.getsize(file_name) == self.meta_dict['size'] \
                and calc_sha1(read_in_chunk(file_name), hexdigest=True) == self.meta_dict['sha1']:
            log("文件已存在, 且与服务器端内容一致")
            return False
        elif CheckDuplicate.is_overwritable(file_name, force):
            with open(file_name, "rb") as f:
                for index, block_dict in enumerate(self.meta_dict['block']):
                    f.seek(self._block_offset(index))
                    if not(calc_sha1(f.read(block_dict['size']),
                            hexdigest=True) == block_dict['sha1']):
                        self.block_list.append(index)
                log(f"{len(self.block_list)}/{len(self.meta_dict['block'])}个分块待下载")
                return True

    def _block_offset(self, index):
        return sum(self.meta_dict['block'][i]['size'] for i in range(index))

    def file_download(self):
        file_name = self.args.file

        mode = "rb+" if os.path.exists(file_name) else "wb"
        with open(file_name, mode) as self.fp:
            for index in self.block_list:
                if len(self.thread_pool) >= self.args.threads:
                    self.done_flag.acquire()
                if not self.terminate_flag.is_set():
                    self.thread_pool.append(
                        threading.Thread(target=self._content_download,
                            args=(index, self.meta_dict['block'][index])))
                    self.thread_pool[-1].start()
                else:
                    log("已终止下载, 等待线程回收")
                    break
            for thread in self.thread_pool:
                thread.join()
            if self.terminate_flag.is_set():
                return None
            self.fp.truncate(sum(block['size']for block in self.meta_dict['block']))
        return None

    def _content_download(self, index, block_dict):
        try:
            for i in range(5):
                if self.terminate_flag.is_set():
                    return None
                block = self._commit_download(block_dict['url'])
                if not block:
                    log(f"分块{index + 1}/{len(self.meta_dict['block'])}第{i + 1}次下载失败")
                # todo block_dict
                elif calc_sha1(block, hexdigest=True) == block_dict['sha1']:
                    self.file_lock.acquire()
                    self.fp.seek(self._block_offset(index))
                    self.fp.write(block)
                    self.file_lock.release()
                    log(f"分块{index + 1}/{len(self.meta_dict['block'])}下载完毕")
                    self.done_flag.release()
                    return
                else:
                    log(f"分块{index + 1}/{len(self.meta_dict['block'])}校验未通过")
            # indicates some error in downloading
            self.done_flag.release()
            self.terminate_flag.set()
        except Exception as e:
            self.terminate_flag.set()
            warn(e)
            return

    def _request(self,url,probe_mode=False):
        headers = {
            'Referer': "http://t.bilibili.com/",
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
        }
        content = []
        last_chunk_time = None
        try:
            with requests.get(url, headers=headers, timeout=10, stream=True) as req:
                if  probe_mode:
                    return req.status_code
                for chunk in req.iter_content(256*1024):
                    if last_chunk_time and time.time()-last_chunk_time > 5:
                        return None
                    content.append(chunk)
                    last_chunk_time = time.time()
            bdata = b"".join(data for data in content)
        except Exception as e:
            warn(e)
            bdata=b""
        return bdata


    def _commit_download(self, url):
            bdata=self._request(url)
            img = ImageConverter(self.args)           
            return  img.image_decode(bdata) if bdata else None
             

    def verify_hash(self):
        try:
            log(f"{os.path.basename(self.args.file)} ({size_string(self.meta_dict['size'])}) 下载完毕, 用时{time.time() - self.start_time:.1f}秒, 平均速度{size_string(self.meta_dict['size'] / (time.time() - self.start_time))}/s")
        except Exception as e:
            warn(e)
            return False
        sha1 = calc_sha1(read_in_chunk(self.args.file), hexdigest=True)
        if sha1 == self.meta_dict['sha1']:
            log("文件校验通过")
            return True
        else:
            log("文件校验未通过")
            return False

    def run(self):
        if self.probe_meta() == False:
            return
        if self.resist_check() == False:
            return
        self.file_download()
        self.verify_hash()

if __name__ == "__main__":
    """
    uargs=UArgs("operate.pdf","bilibiliMinus","nopassword")
    upload=UploadClass(uargs)
    upload.run()
    """
    link="bdrive://cf7f63206639ce788276af636b55f3d724ab1f02"
    dargs=DArgs(link)
    download=DownloadClass(dargs)
    download.run()
