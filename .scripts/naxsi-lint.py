#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import sys
import re
import shlex

DESCRIPTION='Naxsi Rule Linter'
EPILOG='''
This tool lints naxsi rules
Example:
	$ python naxsi-lint.py --rule /path/to/file.rules --output output.rules --begin-id 4200000
'''

def clean_token(token):
	if not token.startswith('"'):
		return token
	return token[1:-1]

def find_keyword(keyword, tokens):
	for token in tokens:
		token = clean_token(token)
		if token.startswith(keyword):
			return token
	return None


class Rule(object):
	def __init__(self, tokens, line_num, comments):
		super(Rule, self).__init__()
		self.line_num = line_num
		self.comments = comments
		self.main_rule = find_keyword("MainRule", tokens)
		self.basic_rule = find_keyword("BasicRule", tokens)
		self.id = find_keyword("id:", tokens)
		self.msg = find_keyword("msg:", tokens)
		self.str = find_keyword("str:", tokens)
		self.rx = find_keyword("rx:", tokens)
		self.mz = find_keyword("mz:", tokens)
		self.s = find_keyword("s:", tokens)
		self.wl = find_keyword("wl:", tokens)
		self.d = find_keyword("d:libinj_", tokens)
		self.negative = find_keyword("negative", tokens)

		# validate first
		self.validate()

		if self.wl != None:
			ids = list(set(self.wl[3:].split(',')))
			ids.sort()
			self.wl = 'wl:' + ','.join(ids)
		else:
			self.id = int(self.id[3:])
		if self.msg != None:
			self.msg = re.sub(r'\s+', ' ', self.msg.strip())
			self.msg = re.sub(r'"', '\'', self.msg.strip())

	def validate(self):
		if self.main_rule == None and self.basic_rule == None:
			print("ERROR: {}: missing 'MainRule' or 'BasicRule' prefix".format(self.line_num))
			sys.exit(1)
		if self.main_rule != None and self.basic_rule != None:
			print("ERROR: {}: 'MainRule' and 'BasicRule' are set".format(self.line_num))
			sys.exit(1)

		if self.id == None and self.wl == None:
			print("ERROR: {}: missing 'id:' or 'wl:'".format(self.line_num))
			sys.exit(1)
		elif self.id != None and self.wl != None:
			print("ERROR: {}: 'id:' and 'wl:' are both set".format(self.line_num))
			sys.exit(1)

		if self.is_whitelist():
			if self.mz == None:
				print("ERROR: {}: missing whitelist 'mz:'".format(self.line_num))
				sys.exit(1)
			elif self.str != None:
				print("ERROR: {}: 'str:' is set for a whitelist".format(self.line_num))
				sys.exit(1)
			elif self.rx != None:
				print("ERROR: {}: 'rx:' is set for a whitelist".format(self.line_num))
				sys.exit(1)
			elif self.d != None:
				print("ERROR: {}: 'd:' is set for a whitelist".format(self.line_num))
				sys.exit(1)
		else:
			self.match()
			if self.mz == None:
				print("ERROR: {}: missing rule 'mz:'".format(self.line_num))
				sys.exit(1)
			if self.s == None:
				print("ERROR: {}: missing rule 's:'".format(self.line_num))
				sys.exit(1)
			
	def prefix(self):
		return self.main_rule if self.main_rule != None else self.basic_rule

	def match(self):
		if self.rx != None:
			return self.rx
		elif self.str != None:
			return self.str
		elif self.d != None:
			return self.d
		print("ERROR: {}: missing rule 'rx:' or 'str:' or 'd:'".format(self.line_num))
		sys.exit(1)

	def is_whitelist(self):
		return self.wl != None

	def message(self):
		if self.msg == None:
			return "match " + self.match().replace('"', '')
		return self.msg[4:]

	def print(self):
		if len(self.comments) > 0:
			print('\n'.join(self.comments))
		prefix = self.prefix()
		args = []
		if self.is_whitelist():
			args = [
				self.wl,
				self.negative,
				'"{}"'.format(self.mz),
				'"{}"'.format(self.msg),
			]
		else:
			args = [
				'id:{}'.format(self.id),
				'"{}"'.format(self.s),
				self.negative,
				'"{}"'.format(self.match()),
				'"{}"'.format(self.mz),
				'"{}"'.format(self.msg),
			]
		args = list(filter(lambda x: x != None and x != '"None"', args))
		print("{} {};".format(self.prefix(), ' '.join(args)))

def parse_file(filename, rules, whitelists, ruleid):
	lines = []
	with open(filename, 'r') as fp:
		lines = fp.readlines()

	line_num = 0
	comments = []
	for line in lines:
		line_num += 1
		line = line.strip()
		if line.startswith("#") or len(line) < 1:
			comments.append(line)
			continue
		elif '#' in line and not '#"' in line and not line.endswith(';'):
			comments.append('#' + line.split('#', 1)[-1])
			line = line.split('#')[0]

		if not line.endswith(';'):
			print("ERROR: {}: missing ; at the end the line '{}'".format(line_num, line))
			sys.exit(1)

		line = re.sub(r';$', " ;", line)
		tokens = shlex.split(line, posix=False)
		# print("{}: {}".format(line_num, tokens))

		rule = Rule(tokens, line_num, comments)
		comments = []

		if rule.is_whitelist():
			whitelists.append(rule)
			continue

		if ruleid > 100:
			rule.id = ruleid
			ruleid += 1
		elif rule.id in rules:
			print("ERROR: {}: Rule {} already exists at line {}".format(line_num, rule.id, rules[rule.id].line_num))
			sys.exit(1)

		rules[rule.id] = rule

def print_rules(rules_ids, rules, whitelists):
	header = len(rules_ids) < 1
	if len(whitelists) > 0:
		for whitelist in whitelists:
			if not header:
				header = True
				print('#############')
				print("# Whitelist #")
				print('#############')
			whitelist.print()

	for idx in rules_ids:
		if header:
			header = False
			print('#########')
			print("# Rules #")
			print('#########')
		rules[idx].print()

def print_translate_dictionary(rules_ids, rules, whitelists):
	for idx in rules_ids:
		print('"{}","{}"'.format(rules[idx].id, rules[idx].message()))

output_formats = {
	'rules': print_rules,
	'logstash_translate_dictionary': print_translate_dictionary,
}

def main():
	parser = argparse.ArgumentParser(usage='%(prog)s [options]', description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-r', '--rule', default='', help='source rule to parse')
	parser.add_argument('-o', '--output', default='', help='path to the output file')
	parser.add_argument('-f', '--format', default='rules', help='format of the output file ({})'.format(','.join(list(output_formats.keys()))))
	parser.add_argument('-b', '--begin-id', default=0, type=int, help='rebase all rules ids from this id number (id must be > 100)')
	args = parser.parse_args()

	if len(sys.argv) == 1 or \
		len(args.rule) < 1 or \
		len(args.output) < 1 or \
		len(args.format) < 1 or \
		args.format not in output_formats or \
		(args.begin_id != 0 and args.begin_id <= 100):
		parser.print_help(sys.stderr)
		sys.exit(1)

	rules = {}
	whitelists = []

	parse_file(args.rule, rules, whitelists, args.begin_id)

	rules_ids = list(rules.keys())
	rules_ids.sort()

	file_format = output_formats[args.format]

	fd = sys.stdout
	if args.output != '-':
		sys.stdout = open(args.output, 'w')

	file_format(rules_ids, rules, whitelists)

	if args.output != '-':
		sys.stdout.close()
		sys.stdout = fd

if __name__ == '__main__':
	main()