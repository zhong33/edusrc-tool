#-*- encoding: utf-8 -*-
import re
import os
import sys
import time
import json
import requests
from bs4 import BeautifulSoup
from collections import Counter
from threading import Thread, Lock
from pyecharts.charts import Bar, Pie, Page
from pyecharts import options as opts
from pyecharts.components import Table, Image
from pyecharts.options import ComponentTitleOpts

class GetInfo(Thread):
    def __init__(self, pages, url, otype):
        super().__init__()
        self.daemon = True
        self.pages = pages
        self.type = otype
        self.url = url
        self.lock = Lock()
    
    def run(self):
        if self.type == 0:
            for i in self.pages:
                url = self.url + "/user/sum/?page=%d" % i
                res = requests.get(url)
                userid = re.findall(re.compile(r'(?<=/profile/)\d*(?=/)'), res.text)
                username = re.findall(re.compile(r'(?<=/" >).*(?=</a>)'), res.text)
                self.lock.acquire()
                try:
                    for (uname,uid) in zip(username,userid):
                        UserInfoDict.update({uname:uid})
                finally:
                    self.lock.release()
        else:
            for i in self.pages:
                url = self.url + "/rank/firm/?page=%d" % i
                res = requests.get(url)
                schoolid = re.findall(re.compile(r'(?<=/list/firm/)\d*(?=">)'), res.text)
                schoolname = re.findall(re.compile(r'(?<=">).*(?=</a>\n                    </td>)'), res.text)
                self.lock.acquire()
                try:
                    for (sname,sid) in zip(schoolname,schoolid):
                        SchoolInfoDict.update({sname:sid})
                finally:
                    self.lock.release()

class GetDetails(Thread):
    def __init__(self, pages, obj):
        super().__init__()
        self.daemon = True
        self.pages = pages
        self.url = obj.baseurl
        self.lock = Lock()
        self.obj = obj

    def run(self):
        for i in self.pages:
            url = self.url + "/profile/%d/?page=%d" % (int(UserInfoDict[self.obj.sid]),i) if self.obj.type == 0 else self.url + "/list/firm/%d?page=%d" % (int(SchoolInfoDict[self.obj.sid]),i)
            res = requests.get(url)
            self.lock.acquire()
            try:
                self.obj.csrfNum += res.text.count("CSRF漏洞")
                self.obj.sqlNum += res.text.count("SQL注入漏洞")
                self.obj.ssrfNum += res.text.count("SSRF漏洞")
                self.obj.xssNum += res.text.count("XSS漏洞")
                self.obj.codeexeNum += res.text.count("代码执行漏洞")
                self.obj.otherNum += res.text.count("其他漏洞")
                self.obj.cmdexeNum += res.text.count("命令执行漏洞")
                self.obj.verticalNum += res.text.count("垂直权限绕过")
                self.obj.weakpwdNum += res.text.count("弱口令")
                self.obj.ifodisNum += res.text.count("敏感信息泄露")
                self.obj.uploadNum += res.text.count("文件上传漏洞")
                self.obj.levelNum += res.text.count("水平权限绕过")
                self.obj.clickNum += res.text.count("水平劫持漏洞")
                self.obj.low += res.text.count("低危</span>")
                self.obj.middle += res.text.count("中危</span>")
                self.obj.high += res.text.count("高危</span>")
                self.obj.serious += res.text.count("严重</span>")
            finally:
                self.lock.release()

class GetList(Thread):
    def __init__(self, pages, url):
        super().__init__()
        self.url = url
        self.pages = pages
        self.lock = Lock()

    def run(self):
        for i in self.pages:
            url = self.url + "&page=%d" % i
            res = requests.get(url)
            username = re.findall(re.compile(r'(?<=/" >).*(?=</a>)'), res.text)
            userrank = re.findall(re.compile(r'(?<=<td class="am-text-center">)\d*(?=</td>\n  </tr>)'), res.text)
            self.lock.acquire()
            try:
                for (uname, urank) in zip(username, userrank):
                    MonthRank.update({uname: int(urank)})
            finally:
                self.lock.release()

class Edusrc(object):
    def __init__(self):
        self.baseurl = "https://src.sjtu.edu.cn"

    def dumpsUserInfo(self):
        url = self.baseurl + "/user/sum/"
        res = requests.get(url)
        maxPage = int(re.findall(re.compile(r'(?<=page=)\d*(?=\D)'), res.text)[-2])
        pagelist = [_ for _ in range(1,maxPage)]
        threads = [GetInfo(pagelist[i:i+5], self.baseurl, 0) for i in range(0,maxPage + 1,5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        jsonstr = json.dumps(UserInfoDict)
        with open("UserInfo.json", "w") as f:
            f.write(jsonstr)
    
    def loadUserInfo(self):
        global UserInfoDict
        with open("UserInfo.json", "r") as f:
            UserInfoDict = json.load(f)

    def dumpsSchoolInfo(self):
        url = self.baseurl + "/rank/firm/"
        res = requests.get(url)
        maxPage = int(re.findall(re.compile(r'(?<=page=)\d*(?=\D)'), res.text)[-2])
        pagelist = [_ for _ in range(1,maxPage)]
        threads = [GetInfo(pagelist[i:i+5], self.baseurl, 1) for i in range(0,maxPage + 1,5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        jsonstr = json.dumps(SchoolInfoDict)
        with open("SchoolInfo.json", "w") as f:
            f.write(jsonstr)
    
    def loadSchoolInfo(self):
        global SchoolInfoDict
        with open("SchoolInfo.json", "r") as f:
            SchoolInfoDict = json.load(f)

class User(object):
    def __init__(self, uid):
        self.type = 0
        self.sid = uid
        self.baseurl = "https://src.sjtu.edu.cn"
        self.csrfNum = self.sqlNum = self.ssrfNum = self.xssNum = self.codeexeNum = self.otherNum = self.cmdexeNum = self.verticalNum = self.weakpwdNum = self.ifodisNum = self.uploadNum = self.levelNum = self.clickNum = self.low = self.middle = self.high = self.serious = 0

    def getUserInfo(self):
        url = self.baseurl + "/profile/%d/" % int(UserInfoDict[self.sid])
        res = requests.get(url)
        self.imgsrc = "https://src.sjtu.edu.cn/" + re.findall(re.compile(r'(?<=<img src=").*(?=" alt=)'), res.text)[0]
        self.rank = int(re.findall(re.compile(r'(?<=Rank： )\d*'), res.text)[0])
        self.bugTotal = int(re.findall(re.compile(r'(?<=总提交漏洞数量： )\d*'), res.text)[0])
        self.bugTotalEffective = int(re.findall(re.compile(r'(?<=已审核通过漏洞数量： )\d*'), res.text)[0])
        self.passingRate = "%.2f%%" % (self.bugTotalEffective / self.bugTotal*100)
        self.averageRank = "%.2f" % (self.rank / self.bugTotalEffective)
        maxPage = int(re.findall(re.compile(r'(?<=page=)\d*(?=\D)'), res.text)[-2]) if re.findall(re.compile(r'(?<=page=)\d*(?=\D)'), res.text) else 1
        pagelist = [_ for _ in range(1,maxPage + 1)]
        threads = [GetDetails(pagelist[i:i+3], self) for i in range(0,maxPage + 1,3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return self

class School(object):
    def __init__(self, sid):
        self.type = 1
        self.sid = sid
        self.baseurl = "https://src.sjtu.edu.cn"
        self.csrfNum = self.sqlNum = self.ssrfNum = self.xssNum = self.codeexeNum = self.otherNum = self.cmdexeNum = self.verticalNum = self.weakpwdNum = self.ifodisNum = self.uploadNum = self.levelNum = self.clickNum = self.low = self.middle = self.high = self.serious = 0
    
    def getSchoolInfo(self):
        url = self.baseurl + "/list/firm/%d" % int(SchoolInfoDict[self.sid])
        res = requests.get(url)
        self.rank = int(re.findall(re.compile(r'(?<=漏洞威胁值：)\d*'), res.text)[0])
        self.bugTotalEffective = self.bugTotal = int(re.findall(re.compile(r'(?<=漏洞总数：)\d*'), res.text)[0])
        self.averageRank = "%.2f" % (self.rank / self.bugTotal)
        maxPage = int(re.findall(re.compile(r'(?<=page=)\d*(?=\D)'), res.text)[-2]) if re.findall(re.compile(r'(?<=page=)\d*(?=\D)'), res.text) else 1
        pagelist = [_ for _ in range(1,maxPage + 1)]
        threads = [GetDetails(pagelist[i:i+3], self) for i in range(0,maxPage + 1,3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return self

class Charts(object):
    def __init__(self, obj):
        self.obj = obj
        self.page =  Page(page_title=self.obj.sid + "edusrc 信息")
    
    def bar(self):
        bugKind = ["XSS漏洞", "敏感信息泄露", "点击劫持漏洞", "CSRF漏洞", "水平权限绕过", "垂直权限绕过", "弱口令", "SQL注入漏洞", "SSRF漏洞", "文件上传漏洞", "代码执行漏洞", "命令执行漏洞", "其他漏洞"]
        bugNum = [self.obj.xssNum, self.obj.ifodisNum, self.obj.clickNum, self.obj.csrfNum, self.obj.levelNum, self.obj.verticalNum, self.obj.weakpwdNum, self.obj.sqlNum, self.obj.ssrfNum, self.obj.uploadNum, self.obj.codeexeNum, self.obj.cmdexeNum, self.obj.otherNum]
        data = list(zip(bugKind, bugNum))
        data.sort(key = lambda x:(x[1]))
        bugKindFinal = [x[0] for x in data]
        bugNumFinal = [x[1] for x in data]
        bar = (
            Bar()
            .add_xaxis(bugKindFinal)
            .add_yaxis("", bugNumFinal)
            .set_global_opts(
                title_opts = opts.TitleOpts(title = "各漏洞情况表", pos_left = "center"),
                xaxis_opts = opts.AxisOpts(name="漏洞类型", axislabel_opts = opts.LabelOpts(rotate = 30, margin = 20)),
                yaxis_opts = opts.AxisOpts(name="数量"),
                datazoom_opts = opts.DataZoomOpts(type_ = "inside"),
            )
        )
        self.page.add(bar)

    def pie1(self):
        xData = ['已通过', '未通过']
        yData = [self.obj.bugTotalEffective, self.obj.bugTotal - self.obj.bugTotalEffective]
        pie1 = (
            Pie()
            .add(
                "", [list(z) for z in zip(xData, yData)],
                radius = ["50%", "70%"],
                label_opts = opts.LabelOpts(is_show = False, position = "center")
            )
            .set_colors(["#2ecc71", "#d53a35"])
            .set_global_opts(
                title_opts = opts.TitleOpts(title = "有效漏洞情况图", pos_left = "center"),
                legend_opts = opts.LegendOpts(type_ = "scroll", pos_left = "5%", pos_top = "35%", orient = "vertical")   
            )
        )
        self.page.add(pie1)
    
    def pie2(self):
        bugLevel = ["低危", "中危", "高危", "严重"]
        bugNum = [self.obj.low, self.obj.middle, self.obj.high, self.obj.serious]
        pie2 = (
            Pie()
            .add("", [list(z) for z in zip(bugLevel, bugNum)])
            .set_colors(["#d48265", "#6ab0b8", "#2f4554", "#c23531"])
            .set_global_opts(
                title_opts = opts.TitleOpts(title = "各级别漏洞情况图", pos_left = "center"),
                legend_opts = opts.LegendOpts(type_ = "scroll", pos_right = "5%", pos_top = "35%", orient = "vertical")   
            )
        )
        self.page.add(pie2)
    
    def table(self):
        table = Table()
        if self.obj.type == 0:
            headers = ["用户名", "Rank", "平均Rank", "通过率"]
            rows = [[self.obj.sid, self.obj.rank, self.obj.averageRank, self.obj.passingRate]]
            title = self.obj.sid + "个人信息"
        else:
            headers = ["单位", "Rank", "平均Rank"]
            rows = [[self.obj.sid, self.obj.rank, self.obj.averageRank]]
            title = self.obj.sid + "信息"
        table.add(headers, rows)
        table.set_global_opts(title_opts = ComponentTitleOpts(title = title, title_style = {"style": "text-align:center;font-weight:800;"}))
        self.page.add(table)

    def image(self):
        image = Image()
        image.add(
            src = (self.obj.imgsrc),
            style_opts={"width": "100px", "height": "100px", "style": "margin-top: 20px;border-radius:50%;"}
        )
        self.page.add(image)

    def render(self):
        self.page.render("result.html")
        with open("result.html", "r+", encoding='utf-8') as html:
            html_bf = BeautifulSoup(html, 'lxml')
            divs = html_bf.select('.chart-container')
            if self.obj.type == 0:
                divs[0]["style"] = "width:100px;height:142px;padding-left:250px;margin-top:200px;margin-bottom:-190px;"
                divs[1]["style"] = "width:315px;height:161px;padding-left:350px;"
                divs[2]["style"] = "width:464px;height:322px;top:10px;left:29px;"
                divs[3]["style"] = "width:571px;height:321px;top:-340px;left:335px;"
                divs[4]["style"] = "width:958px;height:545px;top:-900px;left:885px;"
            else:
                divs[0]["style"] = "width:315px;height:161px;padding-left:350px;margin-top:200px;"
                divs[1]["style"] = "width:464px;height:322px;top:10px;left:29px;"
                divs[2]["style"] = "width:571px;height:321px;top:-340px;left:335px;"
                divs[3]["style"] = "width:958px;height:545px;top:-900px;left:885px;"
            html_new = str(html_bf)
            html.seek(0, 0)
            html.truncate()
            html.write(html_new)
            html.close()
        os.system("result.html")

class Show(object):
    def __init__(self, obj):
        self.obj = obj
    
    def show(self):
        if self.obj.type == 0:
            print("[+] 用户：" + self.obj.sid)
        else:
            print("[+] 单位：" + self.obj.sid)
        print("[+] Rank：" + str(self.obj.rank))
        print("[+] 平均Rank：" + str(self.obj.averageRank))
        if self.obj.type == 0:
            print("[+] 通过率：" + str(self.obj.passingRate))
            print("[+] 有效漏洞数量：" + str(self.obj.bugTotalEffective))
        print("[+] 总提交漏洞数量：" + str(self.obj.bugTotal))
        print("[+] 低危漏洞数量：" + str(self.obj.low))
        print("[+] 中危漏洞数量：" + str(self.obj.middle))
        print("[+] 高危漏洞数量：" + str(self.obj.high))
        print("[+] 严重漏洞数量：" + str(self.obj.serious))

class Annuallist(object):
    def __init__(self):
        self.baseurl = "https://src.sjtu.edu.cn/user/month/?year=%d" % time.localtime().tm_year
        self.month = time.localtime().tm_mon
    
    def getDeatils(self, num):
        if num <= 0:
            exit("[+] 所取条数必须大于0，默认为20！")
        YearRank = {}
        for i in range(1, self.month + 1):
            global MonthRank
            MonthRank = {}
            url = self.baseurl + "&month=%d" % i
            res = requests.get(url)
            maxPage = int(re.findall(re.compile(r'(?<=page=)\d*(?=\D)'), res.text)[-2]) if re.findall(re.compile(r'(?<=page=)\d*(?=\D)'), res.text) else 1
            pagelist = [_ for _ in range(1,maxPage + 1)]
            threads = [GetList(pagelist[i:i+3], url) for i in range(0,maxPage + 1,3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            YearRank = dict(Counter(YearRank) + Counter(MonthRank))
        YearRank = sorted(YearRank.items(), key = lambda x:x[1], reverse=True)
        if num > len(YearRank):
            num = len(YearRank)
            YearRank = dict(YearRank)
        else:
            YearRank = dict(YearRank[0:num])
        table = Table(page_title = "edusrc%d 年度榜单 TOP %d" % (time.localtime().tm_year,num))
        YearRankKeys= [_ for _ in YearRank.keys()]
        YearRankValues = [_ for _ in YearRank.values()]
        headers = ["排名", "用户名", "Rank"]
        rows = []
        for i in range(len(YearRank)):
            row = [i + 1, YearRankKeys[i], YearRankValues[i]]
            rows.append(row)
        table.add(headers, rows)
        table.render("result.html")
        os.system("result.html")

def main():
    edusrc = Edusrc()
    if sys.argv[1] == "-new":
        if sys.argv[2] == "user":
            edusrc.dumpsUserInfo()
            print("[+] 用户信息已更新！")
        elif sys.argv[2] == "school":
            edusrc.dumpsSchoolInfo()
            print("[+] 单位信息已更新！")
        else:
            print("[+]" + sys.argv[2] + "参数无效！")
    elif sys.argv[1] == "-u":
        try:
            edusrc.loadUserInfo()
            user = User(sys.argv[2])
            obj = user.getUserInfo()
            show = Show(obj)
            show.show()
            charts = Charts(obj)
            charts.image()
            charts.table()
            charts.pie1()
            charts.pie2()
            charts.bar()
            charts.render()
        except:
            print("[+] 用户名输入错误，不存在该用户！")
    elif sys.argv[1] == "-s":
        try:
            edusrc.loadSchoolInfo()
            school = School(sys.argv[2])
            obj = school.getSchoolInfo()
            show = Show(obj)
            show.show()
            charts = Charts(obj)
            charts.table()
            charts.pie1()
            charts.pie2()
            charts.bar()
            charts.render()
        except:
            print("[+] 单位名称输入错误，不存在该单位！")
    elif sys.argv[1] == "-b":
        annuallist = Annuallist()
        try:
            num = int(sys.argv[2])
        except:
            num = 20
        annuallist.getDeatils(num)

    elif sys.argv[1] == "-help":
        print("[+] 用法：python3 main.py [-new] [-u] [-s] [-b] [-help] target")
        print("[+] 选项：")
        print("        -new   user/school   更新用户/学校信息")
        print("        -u     username      查询用户信息")
        print("        -s     schoolname    查询学校信息")
        print("        -b     num           查询年榜信息")
        print("        -help                帮助信息")
    else:
        print("[+] 参数输入错误，不存在该参数！\n[+] 输入 -help 获取帮助！")

if __name__ == "__main__":
    UserInfoDict = {}
    SchoolInfoDict = {}
    main()