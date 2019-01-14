#!/usr/bin/python
# coding: utf-8
#
# stl_comment.py
#
import idaapi
import idautils
import idc
import re


class STLCommentHandler(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def activate(self, ctx):
		plg = STLCommentPlugin()
		plg.run(ctx)
		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

class STLCommentPlugin(idaapi.plugin_t):
	plg_name = 'STL Comment Plugin'
	act_name = 'Run ' + plg_name
	act_tooltip = act_name
	menu_category = 'Options/'

	flags = idaapi.PLUGIN_KEEP
	comment = plg_name
	help = ''
	wanted_name = plg_name
	wanted_hotkey = 'Ctrl-Alt-S'


	def init(self):
		idaapi.msg('[%s] init. press CTRL+ALT+S in a function.' % (self.plg_name))

		act_desc = idaapi.action_desc_t(
			self.act_name,
			self.plg_name,
			STLCommentHandler(),
			None,
			self.act_tooltip)

		idaapi.register_action(act_desc)
		idaapi.attach_action_to_menu(
			self.menu_category,
			self.act_name,
			idaapi.SETMENU_APP)

		return self.flags


	def term(self):
		idaapi.detach_action_from_menu(self.menu_category, self.act_name)
		idaapi.unregister_action(self.act_name)
		return None


	def run(self, arg):
		self.comment_stl()


	def get_current_function_range(self, current_ea):
		current_function_begin = idaapi.BADADDR
		current_function_end = idaapi.BADADDR
		for functionAddr in idautils.Functions():
			function_begin = idc.GetFunctionAttr(functionAddr, idc.FUNCATTR_START)
			function_end = idc.GetFunctionAttr(functionAddr, idc.FUNCATTR_END)
			if function_begin <= current_ea and function_end >= current_ea:
				current_function_begin = function_begin
				current_function_end = function_end
				break
		
		return current_function_begin, current_function_end


	def get_groomed_stl_functionnames(self):
		stl_names = dict()
		for functionAddr in idautils.Functions():
			functionName = idc.GetFunctionName(functionAddr)
			demangledName = idc.Demangle(functionName, idc.INF_SHORT_DN)
			if demangledName is None:
				continue
			if self.is_related_with_stl(demangledName) != True:
				continue			
			groomed_name = self.groom_stl(demangledName)
			if groomed_name == demangledName:
				continue
			
			stl_names[functionAddr] = groomed_name

		return stl_names


	def is_related_with_stl(self, demangledName):
		if re.search(r'\bstd\:\:', demangledName):
			return True
		return False


	def groom_template_phrase(self, string, pattern_strings):
		processed_string = string
		
		for pattern_string in pattern_strings:
			pattern = re.compile(pattern_string)

			while True:
				match = pattern.search(processed_string)
				if match == None:
					break

				index = match.span()
				matched_string = processed_string[index[0]:index[1]]

				open_bracket_cnt = matched_string.count('<')
				close_bracket_cnt = matched_string.count('>')
				i = 1
				while open_bracket_cnt > close_bracket_cnt:
					matched_string = processed_string[index[0]:index[1]+i]
					open_bracket_cnt = matched_string.count('<')
					close_bracket_cnt = matched_string.count('>')
					i += 1

				processed_string = processed_string.replace(matched_string, '')

		return processed_string


	def groom_stl_phrase(self, string, pattern_string, replace_string):
		processed_string = string
		result = re.sub(pattern_string, replace_string, processed_string)
		if result != processed_string:
			processed_string = result
		return processed_string


	def groom_stl(self, demangledName):
		template_patterns = [
			',?class std::allocator<[a-zA-Z: _,<]*>,?', 
			',?struct std::char_traits<[a-zA-Z: _,<]*>,?'
		]

		groomed_name = self.groom_template_phrase(demangledName, template_patterns)
		groomed_name = self.groom_stl_phrase(groomed_name, r'^public\:\s', '')
		groomed_name = self.groom_stl_phrase(groomed_name, r'^protected\:\s', '')
		groomed_name = self.groom_stl_phrase(groomed_name, r'^private\:\s', '')
		groomed_name = self.groom_stl_phrase(groomed_name, r'\bclass\s', '')
		groomed_name = self.groom_stl_phrase(groomed_name, r'\bstruct\s', '')
		groomed_name = self.groom_stl_phrase(groomed_name, r'\bstd\:\:', '')
		groomed_name = self.groom_stl_phrase(groomed_name, r'\b__cxx\d\d::', '')
		groomed_name = self.groom_stl_phrase(groomed_name, r'\(.*\)', '()')
		groomed_name = self.groom_stl_phrase(groomed_name, r'basic_string<char>', 'string')
		groomed_name = self.groom_stl_phrase(groomed_name, r'basic_string<wchar_t>', 'wstring')
		groomed_name = self.groom_stl_phrase(groomed_name, r'basic_string<unsigned short>', 'wstring')
		groomed_name = self.groom_stl_phrase(groomed_name, r'(\S+)::(~?)\1', r'\2\1')
		groomed_name = self.groom_stl_phrase(groomed_name, r'_Simple_types<(\w*)>', r'\1')
		groomed_name = self.groom_stl_phrase(groomed_name, r'_List_simple_types<(\w*)>', r'\1')

		return groomed_name


	def comment_stl(self):
		idaapi.msg('[%s] start to add comments\n' % (self.plg_name))

		current_ea = idc.here()
		if current_ea == idaapi.BADADDR:
			idaapi.warning('[%s] invalid address!\n' % (self.plg_name))
			return
		
		current_function_begin, current_function_end = self.get_current_function_range(current_ea)
		if current_function_begin == idaapi.BADADDR or current_function_end == idaapi.BADADDR:
			idaapi.warning('[%s] failed to get_current_function_range!\n' % (self.plg_name))
			return

		stl_names = self.get_groomed_stl_functionnames()
		if len(stl_names) == 0:
			idaapi.warning('[%s] not found any stl usages!\n' % (self.plg_name))
			return

		comments_count = 0

		for functionAddr in stl_names:
			xrefs = idautils.CodeRefsTo(functionAddr, False)
			for xref in xrefs:
				if xref >= current_function_begin and xref <= current_function_end:
					comment = stl_names[functionAddr]
					idaapi.msg('[%s] add a comment on %s (%s)\n' % (self.plg_name, hex(xref), comment))
					cfunc = idaapi.decompile(xref)
					tl = idaapi.treeloc_t()
					tl.ea = xref
					tl.itp = idaapi.ITP_BLOCK1
					cfunc.set_user_cmt(tl, comment)
					cfunc.save_user_cmts()
					idaapi.decompile(current_function_begin)
					comments_count += 1

		idaapi.msg('[%s] finished. %d commented\n' % (self.plg_name, comments_count))
		if comments_count > 0:
			idaapi.msg('[%s] now, press F5!\n' % (self.plg_name))
		
		return


def PLUGIN_ENTRY():
	return STLCommentPlugin()
