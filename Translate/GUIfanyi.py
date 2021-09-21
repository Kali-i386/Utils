#!/usr/bin/python3.8
"""
"""
import io
import sys
import time
import gzip
import json
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox
from tkinter import filedialog
from hashlib import md5
from urllib import request, parse
from io import BytesIO

print("当前使用的Python版本：", sys.version)
# === === === === === 变量区 === === === === ===
print("当前使用的系统平台：", sys.platform)

headers_for_yd = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36',
    'Referer': 'http://fanyi.youdao.com/',
    'Origin': 'http://fanyi.youdao.com',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Connection': 'keep-alive',
    'Host': 'fanyi.youdao.com',
    'cookie': '_ntes_nnid=937f1c788f1e087cf91d616319dc536a,1564395185984; OUTFOX_SEARCH_USER_ID_NCOO=; OUTFOX_SEARCH_USER_ID=-10218418@11.136.67.24; JSESSIONID=; ___rl__test__cookies=1'
}


# 有道翻译请求头

# =============================================================

# === === === === === 函数区 === === === === ===

def setmd5(string):
    a = md5(str(string).encode("utf-8"))
    return str(a.hexdigest())


def fileopen():
    afile = filedialog.askopenfilename(filetypes=[('文本文档', '.txt'), ('日志文件', '.log'), ('所有文件', '*.*')])
    try:
        with open(afile, 'r', encoding='utf-8') as fobj:
            inputbox.delete('1.0', 'end')
            inputbox.insert('end', str(fobj.read()))
    except FileNotFoundError:
        return


def filesave():
    afile = filedialog.asksaveasfilename(filetypes=[('Plain Text', '.txt'), ('Others', '*.*')])
    try:
        with open(afile, 'w', encoding='utf-8') as fobj:
            fobj.write(outbox.get('1.0', 'end'))
    except FileNotFoundError or FileExistsError:
        return


def setfont(*args):
    size = sizemenu.get()
    inputbox.config(font="Consolas {}".format(size))
    outbox.config(font="Consolas {}".format(size))


def clear_all():
    inputbox.delete("0.0", "end")
    outbox.delete("0.0", "end")


def translate(msg):
    request_url = "https://fanyi.youdao.com/translate_o?smartresult=dict&smartresult=rule"
    headerstr = '5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'
    bv = setmd5(headerstr)
    ts = str(round(time.time() * 1000))
    salt = ts + '90'
    strexample = 'fanyideskweb' + msg + salt + 'Y2FYu%TNSbMCxc3t2u^XT'
    sign = setmd5(strexample)
    key = msg

    form = {
        "from": "AUTO",
        "to": "AUTO",
        "smartresult": "dict",
        "client": "fanyideskweb",
        #      "type":"AUTO",
        "i": key,
        "salt": salt,
        "sign": sign,
        "bv": bv,
        "ts": ts,
        "doctype": "json",
        "keyfrom": "fanyi.web",
        #       "ue": "UTF-8",
        "version": "2.1",
        'action': "FY_BY_CLICKBUTTON"
        #      "typoresult":"false"
    }

    data = parse.urlencode(form).encode("utf-8")
    print("[*]:  ", data, '\n', form)

    try:
        print("[*]Using Host")
        request1 = request.Request(request_url, data=data, headers=headers_for_yd)
        result = request.urlopen(request1).read()

    except:
        messagebox.showerror("错误", "请检查网络是否正常")
        return

    try:
        print(result.decode())
        if inputbox.get('1.0', 'end') == '\n':
            messagebox.showwarning("提示", "请输入要翻译的文字")
        elif json.loads(result.decode())['errorCode'] == 50:
            messagebox.showerror("错误", "翻译失败，服务端未返回结果")
        elif json.loads(result.decode())['errorCode'] == 40:
            messagebox.showinfo("提示", "似乎没有翻译出结果，请检查你的输入内容")
    except UnicodeDecodeError or io.UnsupportedOperation:
        result = BytesIO(result)
        result = gzip.GzipFile(fileobj=result)
        result = result.read().decode("utf-8")
        result = json.loads(result)
        print(type(result))
        print(result)
        outbox.delete('0.0', 'end')
        try:
            for _ in range(str(result).count('tgt')):
                outbox.insert('end', result['translateResult'][_][0]['tgt'])
                outbox.insert('end', '\n')
        except IndexError:
            pass
        if str(result).count("smartResult") == 1:
            for i in range(len(result['smartResult']['entries'])):
                outbox.insert('end', '\n' + result['smartResult']['entries'][i])


top = tk.Tk()
top.title("翻译机")
top.geometry("+400+20")
top.minsize(400, 530)
top.maxsize(768, 768)

input_var = tk.StringVar()

# === === === === === 容器控件 === === === === ===

framein = ttk.Labelframe(top, text="输入")
framein.pack(padx=2, pady=2, fill="x")

frameout = ttk.Labelframe(top, text="输出")
frameout.pack(padx=2, pady=2, fill="x")

frameset = ttk.Labelframe(top, text="设置")
frameset.pack(padx=2, pady=2, side="bottom", fill="x")

toolbar = tk.Frame(top, relief="raised", bd=5)
toolbar.pack(padx=5, pady=5, fill="both")

# ========================================================


# === === === === === 父窗口内控件 === === === === ===

# 输入框
inputbox = tk.Text(framein, width=40, height=10, font="Consolas 8", wrap="none")
ysbin = tk.Scrollbar(framein)
xsbin = tk.Scrollbar(framein, orient="horizontal")
ysbin.pack(side="right", fill="y")
inputbox.pack(padx=2, pady=2, side="top", fill="both", expand=1)
xsbin.pack(side="bottom", fill="x")
ysbin.config(command=inputbox.yview)
xsbin.config(command=inputbox.xview)
inputbox.config(yscrollcommand=ysbin.set)
inputbox.config(xscrollcommand=xsbin.set)

# 输出框
outbox = tk.Text(frameout, width=40, height=10, bg="#232323", fg="#E7E7E7", font="Consolas 8", wrap="none")
ysbou = tk.Scrollbar(frameout)
xsbou = tk.Scrollbar(frameout, orient="horizontal")
ysbou.pack(side="right", fill="y")
outbox.pack(padx=2, pady=2, side="top", fill="both", expand=1)
xsbou.pack(side="bottom", fill="x")
ysbou.config(command=outbox.yview)
xsbou.config(command=outbox.xview)
outbox.config(yscrollcommand=ysbou.set)
outbox.config(xscrollcommand=xsbou.set)

# 选择字号的尺度条
tk.Label(frameset, text=" 字号：").grid(row=0, column=0)
sizemenu = tk.Scale(frameset, from_=8, to=15, orient="horizontal", tickinterval=1, length=300, command=setfont)
sizemenu.grid(row=0, column=1)

# 其他按钮
try:
    imgopen = tk.PhotoImage(file="fileopen.gif")
    imgsave = tk.PhotoImage(file="filesave.gif")
    imgtran = tk.PhotoImage(file="translate.gif")
    imgclea = tk.PhotoImage(file="clear.gif")
    ttk.Button(toolbar, text="翻译", image=imgtran, compound='top',
               command=lambda: translate(inputbox.get("1.0", "end"))).pack(side="left", fill="both", expand=True,
                                                                           padx=4,
                                                                           pady=4)
    ttk.Button(toolbar, text="清除", image=imgclea, compound='top', command=clear_all).pack(side="right", fill="both",
                                                                                          expand=True, padx=4, pady=4)
    ttk.Button(toolbar, text="打开", image=imgopen, compound='top', command=fileopen).pack(side='right', padx=4, pady=4)
    ttk.Button(toolbar, text="保存", image=imgsave, compound='top', command=filesave).pack(side='left', padx=4, pady=4)

except:
    messagebox.showwarning("警告", "未找到图标文件，按钮将使用纯文本")
    ttk.Button(toolbar, text="翻译",
               command=lambda: translate(inputbox.get("1.0", "end"))).pack(side="left", fill="both", expand=True,
                                                                           padx=4,
                                                                           pady=4)
    ttk.Button(toolbar, text="清除", command=clear_all).pack(side="right", fill="both", expand=True, padx=4, pady=4)
    ttk.Button(toolbar, text="打开", command=fileopen).pack(side='right', padx=4, pady=4)
    ttk.Button(toolbar, text="保存", command=filesave).pack(side='left', padx=4, pady=4)

# ==========================================================

top.mainloop()
