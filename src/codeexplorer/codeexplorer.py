import ida_idaapi


if ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL:
	from codeexplorer64 import *
else:
	from codeexplorer32 import *
