# EDUSRC 漏洞情况统计脚本

## 一、安装使用方法

```bash
git clone https://github.com/Yang-Zhongshan/edusrc-tool
cd edusrc-tool
pip3 install -r requirements.txt
python3 main.py
```

## 二、模块说明

```
edusrc.dumpsSchoolInfo()		    // 重新爬取所有学校信息（edusrc的这个接口较慢，大概需要150s才能爬完一次）
edusrc.dumpsUserInfo()			    // 重新爬去所有用户信息（大概5s）
edusrc.loadUserInfo()			    // 载入已有用户信息
edusrc.loadSchoolInfo()			    // 载入已有学校信息
user = User("杨众山")		  	     // 查询的用户
school = School("江西师范大学")	     // 查询的学校
charts.bar()				        // 漏洞柱形图
charts.pie1()                       // 漏洞种类饼图（显示的不好，待优化）
charts.pie2()                       // 漏洞类型饼图
```

## 三、备注

脚本没有输出文字，但是都已经计算好了，稍微改下脚本即可，变量都保存在了返回对象中，例如

```python
user = User("杨众山")
obj = user.getUserInfo()
print(obj.averageRank)
```

## 四、效果图

![](./user.png)

![](./school.png)