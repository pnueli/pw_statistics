
import string
import numpy as np
import sys
import codecs
from time import time
from unicodedata import normalize 	


MAIN_DIR = '/Users/pnueli/Documents/'
read_path = MAIN_DIR + 'rockyou-withcount.txt'
write_path = MAIN_DIR + 'rockyou-ascii_4.txt'
print "START"
# with codecs.open(read_path,encoding ='utf-8',mode='rb') as rf:
error_count = 0 # 218 in last one
sum_lost_users = 0 # 4302~
with open(read_path,'rb') as rf:
	with open(write_path,'wb') as wf:
		print repr(rf)
		print type(rf)
		# all_data1 = normalize('NFKD',rf.read())
		# all_data2 = all_data1.encode('ascii','ignore')
		# all_lines = all_data.splitlines()
		for line in rf:
		# for line in codecs.iterencode(rf,'utf-8'):
			try:
				#count = line.split()[0]
				#first = line.split()[1]
				#print "c:{}".format(count)
				usr_count = int(line.split()[0])
				new_line = normalize('NFKD',line.decode('utf-8')).encode('ascii','ignore')
				wf.write(new_line)
			except UnicodeDecodeError as e:
				#print "BLA"
				#print "count:{}".format(count)
				# print "maybe_prev={}".format(new_line)
				# print "U_E. line:{}".format(line)
				# print "UNICODE ERROR"
				# print line
				sum_lost_users += usr_count
				error_count += 1
			except ValueError as e:
				# print "VALUE ERROR"
				# print line
				sum_lost_users += usr_count
				error_count += 1

print "FINISH!"
print "errors: {}".format(error_count)
print "users lost: {}".format(sum_lost_users)
