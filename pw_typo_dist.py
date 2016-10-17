import word2keypress as w2kp
from zxcvbn import password_strength
import string
import numpy as np
import sys
from time import time
from unicodedata import normalize 		
import marisa_trie
import itertools

KB = w2kp.kb
TO_KEY_SEQ = KB.word_to_keyseq
BACK_TO_WORD = KB.keyseq_to_word
CHANGE_SHIFT = KB.change_shift
NEARBY_KEYS = KB.keyboard_nearby_chars #### a bit unrealistic
UPPER = str.isupper
def NOTUPPER(x):
	not UPPER(x)
#
KEY_SEQ_2_WORD = KB.keyseq_to_word

SHIFT = '\x03'
CAPS  = '\x04'
MIN_ENT = 10
MIN_REL_ENT = -3

MAIN_DIR = '/Users/pnueli/Documents/'
TRIE_PATH = MAIN_DIR + 'trie_for_all.txt'
NNN = 15

ONLINE_ATTACK = True

def get_pos_typos(pw, pw_ent_bits, count = 1, req_len = 0):
	if not pw:
		return [] # TODO CHANGE
	pw_press = TO_KEY_SEQ(pw)
	# caps lock on/off
	p_caps = 10.9
	p_shift_first = 4.5 # flipped, either on or off
	p_added_end = 4.6
	p_added_front = 1.3
	p_shift_last = 0.2
	p_prox = 21.8
	# out of 100
	sum_p = p_caps + p_shift_first + p_added_front + p_added_end + p_shift_last + p_prox

	#
	sum_p -= p_added_front #
	p_caps = (count * p_caps) / sum_p
	p_shift_first = (count * p_shift_first) / sum_p
	p_added_end = (count * p_added_end) / sum_p
	#p_added_front = (count * p_added_front) / sum_p
	p_shift_last = (count * p_shift_last) / sum_p
	p_prox = (count * p_prox) / sum_p
	#

	# small_sum = p_caps+p_shift_first + p_added_end + p_shift_last + p_prox ## TODO REMOVE
	# print "initial sum: {}".format(small_sum) ## TODO REMOVE
	many_typos = []
	try:
		t_caps = ''.join([CAPS,pw_press]) if pw_press[0] != CAPS else pw_press[1:]
		t_shift_first = ''.join([SHIFT,pw_press]) if pw_press[0] != SHIFT else pw_press[1:]
		t_shift_last = ''.join([pw_press[:-1],SHIFT,pw_press[-1]]) if pw_press[-2] != SHIFT else ''.join([pw_press[:-2],pw_press[-1]])
		tmp_typo_list = [(t_caps,p_caps), (t_shift_last,p_shift_last), (t_shift_first,p_shift_first)]
	except IndexError as e:
		print "skipped steps for {}. Index Error".format(pw)
	#	
	for (typo,pp) in tmp_typo_list:
		typo = BACK_TO_WORD(typo) ###
		typo_ent_bits = password_strength(typo)['entropy'] ###
		too_weak = (typo_ent_bits < MIN_ENT) or ((typo_ent_bits - pw_ent_bits) < MIN_REL_ENT) ###
		if too_weak:
				continue
		many_typos.append((typo,pp))

	# added end - only digits
	zero = ord('0')
	for i in xrange(0,10):
		add_ch = chr(i+zero)
		typo = BACK_TO_WORD(''.join([pw_press,add_ch]))
		typo_ent_bits = password_strength(typo)['entropy'] ###
		too_weak = (typo_ent_bits < MIN_ENT) or ((typo_ent_bits - pw_ent_bits) < MIN_REL_ENT) ###
		if too_weak:
				continue
		many_typos.append((typo, p_added_end/10))
	# addedFront - TODO

	# prox
	length = len(pw_press)
	# print length
	for i in xrange(length):
		c = pw_press[i]
		nearby_chrs = filter(lambda x: not UPPER(x), list(NEARBY_KEYS(c)))
		nearby_len = len(nearby_chrs)
		if not nearby_len:
			continue
		each_p = (1.0 / length) * p_prox * (1.0 / nearby_len)
		for c_t in nearby_chrs:
			typo = BACK_TO_WORD(''.join([pw_press[:i], c_t, pw_press[i+1:]]))
			typo_ent_bits = password_strength(typo)['entropy'] ###
			too_weak = (typo_ent_bits < MIN_ENT) or ((typo_ent_bits - pw_ent_bits) < MIN_REL_ENT) ###
			if too_weak:
				continue
			many_typos.append((typo, each_p))




	# getting only the top length typos
	try:
		if req_len:
			sum_prob_of_req = 0
			ii = min(req_len,len(many_typos)) - 1
			least_p = many_typos[ii][1]
			m_t_len = len(many_typos)
			while (ii < m_t_len) and (many_typos[ii][1] == least_p):
				ii += 1	
			req_typos =  many_typos[:ii]
			for jj in xrange(ii):
				sum_prob_of_req += req_typos[jj][1]
			assert sum_prob_of_req < 1.0000001 # there's a bit of miss-accuracy with float sums
			# if sum_prob_of_req > 1.000000001: ###### there's a bit of miss-accuracy with float sums
			# 	print 'prob_sum:', sum_prob_of_req
			# 	print "bool:", sum_prob_of_req > 1.0
			# 	print "pw '{}'' with too much prob, {} ".format(pw,sum_prob_of_req)
			# 	for ttt in req_typos:
			# 		print ttt
			for jj in xrange(len(req_typos)):
				tt, tt_pp = req_typos[jj]
				req_typos[jj] = (tt, tt_pp / sum_prob_of_req)

	except IndexError as e:
		print "req_L: {}, ii:{}".format(req_len,ii)
		print "pmany_typos[ii]:{}".format(many_typos[ii])
		
	return many_typos


def create_trie_only():
	passwords_path = MAIN_DIR + 'rockyou-ascii.txt' # for quick checks
	#passwords_path = MAIN_DIR + 'rockyou-ascii_3.txt' ##
	#
	another_trie_path = MAIN_DIR + 'myTrieYay.txt'
	all_names = []
	with open(passwords_path,'rb') as ff:
		with open(TRIE_PATH,'wb') as ww:
			# at the end of the file the format is broken. simply deleted it manually
			START = time()
			print ("start:{}".format(START))
			#for line in all_data: #
			
			for line in ff:
				try:
					tup = (line.split())
					count = int(tup[0])
					splitted_str = [x for x in tup[1:]]
					pw = ' '.join(splitted_str)
					pw_ent_bits = password_strength(pw)['entropy']
					all_names.append(pw)
					typos = [tt[0] for tt in get_pos_typos(pw,pw_ent_bits, 1, NNN)]
					all_names = all_names + typos
				except UnicodeError as e: # shouldn't happen because the file manipulation is done before
					print "line: {}".format(line)
					raise e
				except ValueError as e:
					# password contains space so split fails
					print "line: {}".format(line)
					raise e
				except KeyError as e:
					print ("KeyError")
					raise e
			print "finished collecting"
			all_for_trie = marisa_trie.Trie(all_names)
			print "trie createed writing to file"
			all_for_trie.save(another_trie_path)
			for word, code in all_for_trie.items():
				ww.write(" ".join([str(code),str(word),'\n']))


def initiate_with_a_trie_file():
	# so we should only have a list of names + typos

	file_path = MAIN_DIR + 'rockyou-ascii.txt' # for quick checks
	# file_path = MAIN_DIR + 'rockyou-ascii_3.txt' ##

	print "Starting to create the trie"
	# list_for_marisa = []
	# with open(TRIE_PATH,'rb') as trie_file:
	# 	for line in trie_file:
	# 		tup = line.split()
	# 		code = ' '.join(tup[1:])
	# 		# print "code:{}, code length:{}".format(code,len(code)) # TODO REMOVE
	# 		list_for_marisa.append(code)
	# TRIE_ALL = marisa_trie.Trie(list_for_marisa) # TODO CHANGE TO READ FROM FILE

	another_trie_path = MAIN_DIR + 'myTrieYay.txt'
	TRIE_ALL = marisa_trie.Trie()
	TRIE_ALL.load(another_trie_path)
	print "loaded the marisa_trie"
	# print "Trie created with length: {}".format(len(list_for_marisa))
	#
	# NUM_OF_LINES = 10**8 # TODO CHANGE # TRIE SIZE
	NUM_OF_LINES = 265796
	MAX_LENGTH = (15 * 2) + 1
	
	UTF8 = 'utf-8'
	# .dcode(UTF8)
	UNINIT = -1.0
	DEF_LINE = [UNINIT] * MAX_LENGTH
	pw_arr = np.array([DEF_LINE] * NUM_OF_LINES)
	typo_arr = np.array([DEF_LINE] * NUM_OF_LINES)

	SUM_ALL = 1000 # TODO CHANGE according to check

	print "Starting to read from file and collect the data"
	with open(file_path,'rb') as ff:
		# at the end of the file the format is broken. simply deleted it manually
		START = time()
		print ("start:{}".format(START))
		#for line in all_data: #
		count_fails = 0
		for line in ff:
			#try:
			tup = (line.split())
			count = int(tup[0])
			pw_pp = float(count) / SUM_ALL
			splitted_str = [x for x in tup[1:]]
			pw = ' '.join(splitted_str)
			pw_ent_bits = password_strength(pw)['entropy']
			pw_id = TRIE_ALL.key_id(pw.decode(UTF8))
			typos = get_pos_typos(pw,pw_ent_bits, 1, NNN)
			typos_with_id = [(TRIE_ALL.key_id(tt.decode(UTF8)),pp) for (tt,pp) in typos]
			# writing for pw
			pw_arr[pw_id][0] = pw_pp
			index_in_pw_arr = 1
			for tt_id,pp in typos_with_id:
				try:
					# updating pw_array
					pw_arr[pw_id][index_in_pw_arr] = tt_id
					pw_arr[pw_id][index_in_pw_arr + 1] = pp ## this is the probability of having this typo in cache from that pw
					index_in_pw_arr += 2

					# updating typo_arr
					rel_typo_pp = pp * pw_pp # the typo gain probabily based in the pw's prob as well
					old_typo_pp = typo_arr[tt_id][0]
					if old_typo_pp == UNINIT: # AKA un initiated
						typo_arr[tt_id][0] = rel_typo_pp
					else:
						typo_arr[tt_id][0] += rel_typo_pp
					
					index_in_typo_arr = 1
					# will raise error if out of length
					while index_in_typo_arr != UNINIT: # skipping filled
						index_in_typo_arr += 2 #
					typo_arr[tt_id][index_in_typo_arr] = pw_id
					typo_arr[tt_id][index_in_typo_arr + 1] = pp

				except IndexError as e:
					print "reached indexError: pw_I={}, typo_I:{}".format(index_in_pw_arr, index_in_typo_arr)
				
				# adding for thse typos

			# except Exception as e:
			# 	count_fails += 1
			# 	print "failed on something. count={}".format(count_fails)
			# 	raise e

	print "Finished aggregating the data"
	print "Starting to calculate attacks"
	# out of open file, still in def
	# calculating the ATTACK
	QUERIES = 1000
	while QUERIES:
		# find max
		max_score = 0
		max_typo_id = 0
		for typo_id in xrange(NUM_OF_LINES):
			t_p_sum = typo_arr[typo_id][0]
			max_typo_id = typo_id if (t_p_sum != UNINIT and t_p_sum > max_score) else max_typo_id

		# found max
		added_p = typo_arr[max_typo_id][0]
		print "\n"*2, "*"*20 # TODO REMOVE
		print "chose {},({}) with {} users".format(max_typo_id,TRIE_ALL.restore_key(max_typo_id),added_p)
		broken += added_p
		# removing chosen
		typo_arr[max_typo_id][0] = 0 # TODO CHANGE? the easiest way to remove it
		# need to also remove from other pw's
		for index_in_typo_line in xrange(1,MAX_LENGTH,2) : # 2 adjasant indexes are used each time
			# if reached the end of initiated cells:
			if typo_arr[typo_id][index_in_typo_line] == UNINIT:
				break
			pw_id = typo_arr[typo_id][index_in_typo_line]
			pp_of_chosen_typo_for_pw = typo_arr[typo_id][index_in_typo_line + 1]
			print "pw_id:{}, count: {}".format(pw_id,count) # TODO REMOVE
			try :
				# calc new prob of pw
				# update the prob of all the other typos of that pw

				# gaining the prob of chosen typo accuring for that pw

				old_pw_pp = pw_arr[pw_id][0]
				new_pw_pp =  old_pw_pp * (1 - pp_of_chosen_typo_for_pw)
				pw_arr[pw_id][0] = new_pw_pp
				# updating in case it's a typo as well # TODO CHECK _ I think we entered all pws into typo_arr
				typo_arr[pw_id][0] -= (old_pw_pp - new_pw_pp) 
				
				sum_of_rest_typos_pp = 0
				for index_in_pw_arr in xrange(1,MAX_LENGTH,2):
					if index_in_pw_arr == UNINIT:
						break
					sum_of_rest_typos_pp +=  pw_arr[pw_id][index_in_pw_arr + 1]
				assert sum_of_rest_typos_pp  and sum_of_rest_typos_pp < 1 # TODO CHANGE - should be zero otherwise we wouldn't have reached that typo
				# re-normalizing the pp of the pw's typos
				for index_in_pw_arr in xrange(1,MAX_LENGTH,2):
					if index_in_pw_arr == UNINIT:
						break
					tt_id = pw_arr[pw_id][index_in_pw_arr]
					old_tt_pp = pw_arr[pw_id][index_in_pw_arr + 1]
					new_tt_pp = old_tt_pp / sum_of_rest_typos_pp
					pw_arr[pw_id][index_in_pw_arr + 1] = new_tt_pp
					# finding the pw's index in the typo's row (in typo_arr)
					pw_index_in_typo_arr = 1
					while typo_arr[tt_id][pw_index_in_typo_arr] != pw_id:
						pw_index_in_typo_arr += 2
					# should be found - so not checking bounds
					typo_arr[tt_id][0] -= (old_tt_pp - new_tt_pp)
					typo_arr[tt_id][pw_index_in_typo_arr + 1] = new_tt_pp

			except TypeError as e: # TODO REMOVE
				print "bummer"
				raise e

		QUERIES -= 1
	print "BROKEN %: {}".format(broken)

def initiate():
	#file_path = MAIN_DIR + 'rockyou-withcount.txt'
	# file_path = MAIN_DIR + 'rockyou-ascii.txt' # for quick checks
	file_path = MAIN_DIR + 'rockyou-ascii_3.txt' ##
	#with codecs.open(file_path,encoding ='utf-8',mode='rb') as ff: # TODO REMOVE
	with open(file_path,'rb') as ff:
		# at the end of the file the format is broken. simply deleted it manually
		START = time()
		print ("start:{}".format(START))
		pw_d = {}
		typo_d = {}
		#for line in all_data: #
		sum_all_users = 0
		for line in ff:
			try:
				tup = (line.split())
				count = int(tup[0])
				splitted_str = [x for x in tup[1:]]
				pw = ' '.join(splitted_str)
				sum_all_users += count
				if pw in pw_d:
					cc = pw_d[pw]
					pw_d[pw] = count + cc
				else:
					pw_d[pw] = count

			except UnicodeError as e: # shouldn't happen because the file manipulation is done before
				print "line: {}".format(line)
				raise e
			except ValueError as e:
				# password contains space so split fails
				print "line: {}".format(line)
				raise e
			except KeyError as e:
				print ("KeyError")
				raise e
	# out of 'for', out of file
	# for now - pw_d format is-  pw_d[pw] = count
	for pw,pw_count in pw_d.iteritems():
		# on online attack - ALL weak psswords will be part of the possibilities (even if they're weak)
		#if ONLINE_ATTACK:
		pw_pp = float(pw_count) / sum_all_users
		# adding the pw as a possile "typo" - possible attack input
		try:
			typo_sum_pp, pws_with_this_typo = typo_d[pw]
			pws_with_this_typo.append((pw,1))
			typo_d[pw] = (typo_sum_pp + 1, pws_with_this_typo)
		except KeyError: # first time
			typo_d[pw] = (1, [(pw,1)])

		pw_ent_bits = password_strength(pw)['entropy']
		# too_weak =  pw_ent_bits < MIN_ENT
		typos = get_pos_typos(pw,pw_ent_bits, 1, NNN)

		# a weak password might have a strong typo
		# therefore we're not skipping
		#if too_weak: # doesn't enter hashCache
		#	continue
		pw_d[pw] = (pw_pp, typos) 

		for tt,tt_pp in typos:
			actual_tt_pp = tt_pp * pw_pp
			try: #
				sum_p_of_typo, pws_with_this_typo = typo_d[tt]
				pws_with_this_typo.append((pw,actual_tt_pp ))
				typo_d[tt] = (sum_p_of_typo + actual_tt_pp, pws_with_this_typo)
			except KeyError: # first time
				typo_d[tt] = (actual_tt_pp, [(pw,actual_tt_pp)])

	print("empty in dic:{}".format('' in pw_d)) # TODO REMOVE
	print ("Finished building the pw dict. len:{}".format(len(pw_d)))
	print ("Finished building the typo dict. len:{}".format(len(typo_d)))

	print ("Building marisa-trie")
	GLOBAL_TRIE = marisa_trie.Trie([word in itertools.chain(pw_d.keys(),typo_d.keys())])

	pw_save_path = MAIN_DIR + 'pw_left.txt'
	typo_save_path = MAIN_DIR + 'typos_left.txt'
	print ("Starting to build typo dict")

	# WE HAVE DUPLICATE PW from normalizing

	MAX_PW_PER_TYPO = 0
	with open(pw_save_path,'wb') as write_pw:
		with open(typo_save_path,'wb') as write_typo:

			print "converting to marisa-based-ids"

			pw_id_d = {}
			typo_id_d  ={}

			 # if ONLINE ATTACK then pws are in the typo_trie
			 # better for continuity
			print "Creating id dicts, and writing to files"
			UTF8 = 'utf-8'
			for pw,(pw_pp,typo_and_p_list) in pw_d.iteritems():
				# print "pw:{}, count:{}, typ_lis:{}".format(pw,count,typ_lis) # TODO REMOVE
				pw_id = GLOBAL_TRIE.key_id(pw.decode(UTF8))
				typos_id_list = [(GLOBAL_TRIE.key_id((tt).decode(UTF8)),pp) for (tt,pp) in typ_lis]
				pw_id_d[pw_id] = (pw_pp,typos_id_list)
				#
				line  = ' '.join([str(pw_id), str(pw_pp), ' '.join([str(tt)+' '+str(pp) for (tt,pp) in typos_id_list]),'\n'])
				write_pw.write(line)

			for typo,(sum_typo_pp, pw_lis) in typo_d.iteritems():
				# pw_list is [(pw1,p1),(pw2,p22),...]
				MAX_PW_PER_TYPO = max(MAX_PW_PER_TYPO,len(pw_lis))
				typo_id = GLOBAL_TRIE.key_id(typo.decode(UTF8))
				#try:
				pw_id_lis = [ (GLOBAL_TRIE.key_id(pw.decode(UTF8)), pp) for (pw,pp) in pw_lis] # turn to int?
				# except ValueError as e: # TODO REMOVE
				# 	print pw_lis
				# 	raise e 
				typo_id_d[typo_id] = (sum_typo_pp, pw_id_lis) # turn to int ?
				#
				#line = str(typo_id) + ' ' +str(count) + ' ' + ' '.join([str(pw) for pw in pw_id_lis])
				line = ' '.join([str(typo_id), str(sum_typo_pp), ' '.join([str(pw)+' '+str(pw_pp) for (pw,pw_pp) in pw_id_lis]),'\n'])
				write_typo.write(line)

	print "finished converting!"
	print "MAX : {}".format(MAX_PW_PER_TYPO)
	print " saving marisa trie :)"
	marisa_path = MAIN_DIR + "marisa_all.txt"
	with open(marisa_path,'wb') as ff:
		for word,code in GLOBAL_TRIE.items():
			ff.write(' '.join(str(code),str(word)))
	print "finished writing marisa_trie"
	my_count = 0
	for typo in typo_d:
		print("t:{},c:{}".format(typo,typo_d[typo]))
		my_count += 1
		if my_count >= 5:
			break
	my_count = 0
	for pw,(typ_lis) in pw_d.iteritems():
		print("pw: {}, count:{}, typos: {}".format(pw,count,typ_lis))
		my_count += 1
		if my_count >= 5:
			break
	END = time()
	print ("ended: {}".format(END))

	return pw_id_d, typo_id_d, GLOBAL_TRIE




def check1(pw):
	pw_ent_bits = password_strength(pw)['entropy']
	result =  get_pos_typos(pw, pw_ent_bits, 290729)
	result.sort(key=lambda x:x[1],reverse = True)
	print "len:{}".format(len(result))
	for (typ,pp) in result:
		print("typo:{}, pp:{}, strength:{}".format(typ,pp,password_strength(typ)['entropy']))

def calc():
	pw_id_d, typo_id_d, global_trie = initiate()

	print "\n\n\n\n\n\n\n\n" # TODO REMOVE
	print "#"*24, " START ", "#"*24 # TODO REMOVE
	# print "typo_id_d:{}".format(typo_id_d) # TODO REMOVE
	print "\n\n\n\n\n\n\n\n" # TODO REMOVE
	QUERIES = 100
	broken = 0
	while QUERIES:
		# find max
		max_score = 0
		max_typo_id = 0
		for typo_id,(count,_) in typo_id_d.iteritems():
			max_typo_id = typo_id if count > max_score else max_typo_id
		# found max
		count, pw_p_list = typo_id_d[max_typo_id]
		print "\n"*2, "*"*20 # TODO REMOVE
		print "chose {},({}) with {} users".format(typo_id,global_trie.restore_key(typo_id),count)
		print "pw_p_list: {}".format(pw_p_list)
		broken += count
		for (pw_id,_) in pw_p_list:
			count, typo_id_p_list = pw_id_d[pw_id]
			print "pw_id:{}, count: {}".format(pw_id,count) # TODO REMOVE
			print "typo_id_p_list: {}".format(typo_id_p_list) # TODO REMOVE
			try :
				for tt,cc in typo_id_p_list: #################################### <----
					print "updated tt: {} with cc: {}".format(tt,cc)

					_, typo_count, pw_p_list = typo_id_d[tt] 
					print "pw_p_list of ({}): {}".format(tt,pw_p_list) # TODO REMOVE
					try : # TODO REMOVE
						pw_p_list.remove((pw_id,cc))
					except ValueError as e: # TODO REMOVE
						print "VALUE ERROR"
						print "pw_id:{},cc:{}".format(pw_id,cc)

					new_typo_count = typo_count - cc
					typo_id_d[tt] = (tt, new_typo_count, pw_p_list)
					print "into ({}): old_count:{}, new_count:{}".format(tt,typo_count,new_typo_count)
			except TypeError as e: # TODO REMOVE
				print typo_id_p_list
				raise e

		QUERIES -= 1
	print "broken: {}".format(broken)
	return broken

if __name__ == "__main__":
	# print NEARBY_KEYS('1')
	# check1('123456')
	# create_trie_only()

	create_trie_only()
	initiate_with_a_trie_file()
	


