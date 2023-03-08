import re
import urllib3.exceptions
from   bs4 import  BeautifulSoup
import json
import time
import openpyxl
import requests
import sys
from   collections import  Counter


def html_download(url):
    response = requests.get(url=url, verify=False, timeout=3)
    if response:
        with open("xray.html", 'wb') as f:
            f.write(response.content)
        f.close()
    else:
        print("访问X-ray扫描结果失败，请重试")

def stampToTime(stamp):
    datatime1 = time.strftime ("%Y-%m-%d %H:%M:%S", time.localtime (float (str (stamp)[0:10])))
    return datatime1

def go():
    with open('xray.html', "r", encoding="utf-8") as f:
         str1 = f.read()
    vuln1_info = re.findall(r"<script class='web-vulns'>webVulns.push\((.*?)\)</script>", str1, re.M | re.I)
    dict2 = {}
    dict2_add = []
    dic_a = []
    for i in range(0, len(vuln1_info)):
        dict2_add.append(dict(dict2))
    for info in vuln1_info:
        name1 = vuln1_info.index(info)
        dict1 = json.loads(info)
        dict2_add[name1]["创建时间"] = stampToTime(dict1["create_time"])
        dict2_add[name1]["漏洞链接"] = dict1["target"]["url"]
        dict2_add[name1]["插件名称"] = dict1["plugin"]
        dict2_add[name1]["额外信息"] = dict1["detail"]["extra"]
        for i in range(0, len(dict1["detail"]["snapshot"])):
            request_n = "request%s" % (i + 1)
            response_n = "response%s" % (i + 1)
            dict2_add[name1][request_n] = dict1["detail"]["snapshot"][i][0]
            dict2_add[name1][response_n] = dict1["detail"]["snapshot"][i][1]
            i = int(i) + 1
        dict2_add[name1]["snapshot_len"] = len(dict1["detail"]["snapshot"])
        dic_a.append(dict2_add[name1])
    return dic_a

def cunchu_csv():
    soup = BeautifulSoup(open("xray.html",encoding='utf-8'), 'html.parser')
    addr =soup.find_all("script", class_="web-vulns")
    global  length
    length = int(((str(addr).count('web-vulns'))))
    print("此次扫描总共产生"+str(length)+"条")
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Xray-扫描结果"
    sheet["A1"] = "ID"
    sheet["B1"] = "创建时间"
    sheet["C1"] = "漏洞链接"
    sheet["D1"] = "插件名称"
    sheet["E1"] = "复测结果"
    tagrget = []
    Ti =[]
    chajian = []
    #写入id
    for id in range(1,length+1):
        sheet["A"+str(id+1)] = id
    #写入时间
    for ti in ALL_info:
        Ti.append(ti["创建时间"])
    for n in range(0,length):
            sheet["B"+str(n+2)] = Ti[n]
    #写入漏洞链接
    for i in ALL_info:
        tagrget.append(i["漏洞链接"])
    for c in range(0,length):
        sheet["C"+str(c+2)] = tagrget[c]
    #写入插件名称
    for cha in ALL_info:
        chajian.append(cha["插件名称"])
    for ch in range(0,length):
        sheet["D"+str(ch+2)] = chajian[ch]

    workbook.save("xray_info.xlsx")


def vlun_info():
    plugin_info = []
    for plugin  in go():
        plugin_info.append(plugin["插件名称"])
    result = Counter(plugin_info)
    all = 0
    with open("xray.txt",'w') as f:
        for i in result:
            #print(i + ":" + str(result[i]))
            all += result[i]
            f.write(i+":"+str(result[i])+'\n')
        f.close()

def vlun_check():
    #设置规则库,检测报送最多的几条插件扫描进行复测，其余手工复测
    rules = ['dirscan/admin/default',]
    URL_checklist = []
    after_check_url_no = []
    after_check_url_yes = []
    for i in rules:
        for c in range(0,length):
            if i == ALL_info[c]["插件名称"]:
               URL_checklist.append(ALL_info[c]["漏洞链接"])
    for n in URL_checklist:
        requests.packages.urllib3.disable_warnings()
        try:
            response = requests.get(url=n,verify=False,timeout=5)
            if "统一登录平台" in response.text:
                after_check_url_no.append(n)
            else:
                after_check_url_yes.append(n)
        except Exception as e:
               print(n+"无法访问")
               after_check_url_no.append(n)
    print("完成漏洞复测，正在给漏洞链接打上标签")
    return after_check_url_no , after_check_url_yes

#打标签方法重写
def recheck_info():
    excel = openpyxl.load_workbook("xray_info.xlsx")
    excel2 = excel.worksheets[0]
    #1.对admin/default 标签操作
    for ind, a in enumerate(excel2["C"]):
        for u in n:
            if u == a.value:
                excel2["E" + str(ind + 1)] = 'N'
        for u in y:
            if u == a.value:
                excel2["E"+ str(ind+1)] = 'Y'
    print("完成admin/default标签")
    #2.统一标签操作
    #无危害的扫描插件
    plugin = ["dirscan/sourcemap/default","dirscan/debug/readme","dirscan/sensitive/crossdomain","baseline/sensitive/server-error",'dirscan/debug/default','dirscan/sensitive/statistic']
    for c in plugin:
        for ind, a in enumerate(excel2["D"]):
            if c == a.value:
                excel2["E"+str(ind+1)] = "N"
    #3.有一定危害的插件
    plugin2 = ["dirscan/temp/default", 'dirscan/directory/default', 'dirscan/config/web', 'dirscan/admin/tomcat',
               'dirscan/config/dependence', 'dirscan/config/htaccess']
    for c in plugin2:
        for ind, a in enumerate(excel2["D"]):
            if c == a.value:
                excel2["E" + str(ind + 1)] = "Y"
    print("完成实际危害标签操作,剩余人工复测")
    excel.save("xray_info-" + str(time.strftime("%Y-%m-%d", time.localtime())) + ".xlsx")

if __name__=="__main__":
  print("""
      Xray-result
      eg : python3 main.py http://url/xxx.html
  """)
  html_download(url=sys.argv[1])
  ALL_info = go()
  cunchu_csv()
  vlun_info()
  #vlun_check()
  (n, y) = vlun_check()
  recheck_info()
