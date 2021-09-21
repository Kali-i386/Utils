#!/usr/bin/python3
import re
import PIL
from PIL import Image, ImageTk
import base64
import tkinter as tk
import tkinter.ttk as ttk
import hashlib
from tkinter import Label, messagebox, filedialog

top = tk.Tk()
top.geometry("460x560")
top.title("工具包Util")
top.minsize(460,560)

note = ttk.Notebook(top)
note.pack(padx=5, pady=5, fill="both", expand=True)

tk.Label(top,text="开发者：三亚市第四中学 吴征 2021-9-10",relief="ridge",bd=4,height=8,bg="#3498DB").pack(side="bottom",fill="x",expand=False,padx=5,pady=5)

encryption = ttk.Frame(note)
binary = ttk.Frame(note)
string_code = ttk.Frame(note)
regex = ttk.Frame(note)
img2base64 = ttk.Frame(note)

tag1 = note.add(encryption, text="算法加密")
tag2 = note.add(binary, text="进制转换")
tag3 = note.add(regex, text="正则表达式测试")
tag4 = note.add(img2base64, text="图片转base64")


# <><><><>Encryption<><><><>
# -------------------修改过的代码块：开始------------------------------------------
def set_hash(method="md5"):  # 没有点击下拉框选择时，默认选择md5
    method_dicts = {"请选择(默认md5)：": hashlib.md5, "md5": hashlib.md5, "sha1": hashlib.sha1, "sha224": hashlib.sha224,
                    "sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
    if method in method_dicts:
        m = method_dicts[method]()
        m.update(input_text.get().encode("utf-8"))
        output_text.delete('0', 'end')
        output_text.insert('end', string=m.hexdigest())


# -------------------修改过的代码块：结束------------------------------------------

var = tk.StringVar()
var.set("请选择：")

tk.Label(encryption, text="加密前：").grid(row=0, column=0)
input_text = ttk.Entry(encryption, width=48)
input_text.grid(row=0, column=1)
tk.Label(encryption, text="加密后：").grid(row=1, column=0)
output_text = ttk.Entry(encryption, width=48)
output_text.grid(row=1, column=1)
ttk.Button(encryption, text="加密", command=lambda: set_hash(var.get())).grid(row=2, column=0)
option = ttk.OptionMenu(encryption, var, *("请选择：", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"))
option.grid(row=2, column=1)


# =========================

# <><><><>Binary<><><><>
def wrap():
    try:
        string = bin_input.get(1.0, 'end').strip().lower()
    except ValueError as err:
        messagebox.showerror(title="错误", message="请检查输入：" + str(err))
        return
    bin_output.delete('1.0', 'end')
    method = bin_var.get()
    input_method = inp_var.get()
    try:
        # -------------------修改过的代码块：开始------------------------------------------
        # 此处可以用字典存储进制，以代替分支结构
        bases = {1: 2, 2: 8, 3: 10, 4: 16}
        string = int(bin_input.get(1.0, 'end').strip(), base=bases[input_method])
        # -------------------修改过的代码块：结束------------------------------------------
    except ValueError:
        messagebox.showerror(title="错误",
                             message="请检查输入内容。\n二进制转换只能输入0或1\n八进制转换只能输入0到7\n十进制转换只能输入0到9\n十六进制转换只能输入0到9以及abcdef")
        return

    # 此处可以用字典存储进制，以代替分支结构
    if method == 1:
        bin_output.insert("end", bin(string).lstrip("0b"))
    elif method == 2:
        bin_output.insert("end", oct(string).lstrip("0o"))
    elif method == 3:
        bin_output.insert("end", int(string))
    elif method == 4:
        bin_output.insert("end", hex(string).lstrip("0x"))


frame_input = ttk.Labelframe(binary, text="输入")
frame_input.grid(row=0, column=0, columnspan=5)
radio_bin = tk.Frame(frame_input)
radio_bin.pack(side="bottom", fill="both")

frame_output = ttk.Labelframe(binary, text="输出")
frame_output.grid(row=1, column=0, columnspan=5)
bin_input = tk.Text(frame_input, width=55, height=14)
bin_input.pack(fill="both")
bin_output = tk.Text(frame_output, width=55, height=15)
bin_output.pack(fill="both")
ttk.Button(binary, text="转换", command=wrap).grid(row=2, column=0)

bin_var = tk.IntVar()
bin_var.set(1)

inp_var = tk.IntVar()
inp_var.set(1)

# -------------------修改过的代码块：开始------------------------------------------
bases = ["", "二进制", "八进制", "十进制", "十六进制"]
for i in range(1, 5):
    ttk.Radiobutton(radio_bin, text=bases[i], variable=inp_var, value=i).pack(side="left", fill="both")
    ttk.Radiobutton(binary, text=bases[i], variable=bin_var, value=i).grid(row=2, column=i)


# -------------------修改过的代码块：结束------------------------------------------

# ======================
# <><><><>Regex<><><><>
def execute():
    # 可尝试修改成更简明的代码。提示：充分利用列表或字典存储关键词，使用for循环代替多个if语句等
    li = ["I", "M", "S", "U", "X"]
    for flag in li:
        exec(f"global {flag}\n{flag} = reg_var{str(li.index(flag) + 1)}.get()")

    def reg():
        global total,execstring
        total = 0
        execstring = "global regexobj;regexobj = re.compile(pattern_entry.get()"
        for i in ["I", "M", "S", "U", "X"]:
            exec(f"""
global execstring
if {i} == 1: 
    if total > 0:
        execstring = execstring + "|re.{i}"
    else:
        execstring = execstring + ",re.{i}"
        total += 1
""")
        execstring = execstring + ")"
        print(execstring)
        return execstring

    execstring = reg()
    try:
        exec(execstring)
    except re.error:
        messagebox.showerror(message="语法错误(引发了re.error异常)")
        return
    text = tomatch.get(1.0, 'end')
    if text.strip() == "":
        messagebox.showwarning(title="提示", message="请输入要匹配的文字")
        return
    result = regexobj.match(text)
    match.delete(0, 'end')
    if result is not None:
        try:
            try:
                for e in range(32767):
                    print("Result", result.group(e + 1))
                    match.insert('end', result.group(e + 1))
            except IndexError:
                pass
        except AttributeError as err:
            messagebox.showinfo(title="提示", message=str(err))
            return


etyframe = ttk.Labelframe(regex, text="表达式")
etyframe.pack(fill="both")
tomatchframe = ttk.Labelframe(regex, text="待匹配的文本")
tomatchframe.pack(fill="both")
matchframe = ttk.Labelframe(regex, text="输出")
matchframe.pack(fill="both")

pattern_entry = ttk.Entry(etyframe, width=55)
pattern_entry.pack(fill="x")
tomatch = tk.Text(tomatchframe, width=55, height=8)
tomatch.pack(fill="both")
match = tk.Listbox(matchframe)
match.pack(fill="both")
reg_tool = tk.Frame(regex)
reg_tool.pack(side="bottom", fill="both", expand=True)

for i in range(6):
    exec("reg_var{} = tk.IntVar()".format(str(i + 1)))

re_button = ttk.Button(reg_tool, text="匹配", command=execute, width=8)
re_button.pack(side="left", fill="both", padx=5, pady=5)

ttk.Checkbutton(reg_tool, text="忽略大小写", variable=reg_var1).pack(side="top", fill="both")
ttk.Checkbutton(reg_tool, text="多行匹配", variable=reg_var2).pack(side="top", fill="both")
ttk.Checkbutton(reg_tool, text="匹配包括换行在内的所有字符", variable=reg_var3).pack(side="top", fill="both")
ttk.Checkbutton(reg_tool, text="根据Unicode字符集解析字符", variable=reg_var4).pack(side="top", fill="both")
ttk.Checkbutton(reg_tool, text="更灵活的格式", variable=reg_var5).pack(side="top", fill="both")


# ======================

# <><><><>Img to Base64 <><><><>
def openimage():
    global filename
    filename = filedialog.askopenfilename(
        filetypes=[("PNG", ".png"), ("JPG", ".jpg"), ("Bitmap", ".bmp"), ("X Bitmap", ".xbm"), ("JPEG", ".jpeg"),
                   ("X Pixmap", ".xpm"), ("GIF", ".gif"), ("Windows icon", ".ico"), ("All files", "*.*")])
    with open(filename, 'rb') as file_object:
        data = base64.b64encode(file_object.read())
        b64_text = data.decode()
        show_b64.delete(1.0, "end")
        show_b64.insert("end", b64_text)


def view():
    level = tk.Toplevel()
    try:
        image = Image.open(filename)
        image = ImageTk.PhotoImage(image)
    except PIL.UnidentifiedImageError:
        messagebox.showerror(title="错误", message="这似乎不是图片文件，但它仍可以转换成Base64编码")
        return
    except NameError:
        return
    tk.Label(level, image=image).pack(fill="both", expand=True)
    level.mainloop()

xscroll = ttk.Scrollbar(img2base64)
xscroll.pack(side="right",fill="y")

show_b64 = tk.Text(img2base64, width=60, height=32,yscrollcommand=xscroll.set)
show_b64.place(x=0, y=0)
xscroll.config(command=show_b64.yview)

ttk.Button(img2base64, text="打开图片文件", command=openimage).place(x=5, y=5)
ttk.Button(img2base64, text="预览原图片", command=view).place(x=90, y=5)
# =============================

top.mainloop()
print("Process Finished.")
