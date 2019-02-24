#coding=utf8
#author : veritas501
from pwn import *


_IO_FILE_plus_size = {
	'i386':0x98,
	'amd64':0xe0
}
_IO_FILE_plus = {
	'i386':{
		0x0:'_flags',
		0x4:'_IO_read_ptr',
		0x8:'_IO_read_end',
		0xc:'_IO_read_base',
		0x10:'_IO_write_base',
		0x14:'_IO_write_ptr',
		0x18:'_IO_write_end',
		0x1c:'_IO_buf_base',
		0x20:'_IO_buf_end',
		0x24:'_IO_save_base',
		0x28:'_IO_backup_base',
		0x2c:'_IO_save_end',
		0x30:'_markers',
		0x34:'_chain',
		0x38:'_fileno',
		0x3c:'_flags2',
		0x40:'_old_offset',
		0x44:'_cur_column',
		0x46:'_vtable_offset',
		0x47:'_shortbuf',
		0x48:'_lock',
		0x4c:'_offset',
		0x54:'_codecvt',
		0x58:'_wide_data',
		0x5c:'_freeres_list',
		0x60:'_freeres_buf',
		0x64:'__pad5',
		0x68:'_mode',
		0x6c:'_unused2',
		0x94:'vtable'
	},

	'amd64':{
		0x0:'_flags',
		0x8:'_IO_read_ptr',
		0x10:'_IO_read_end',
		0x18:'_IO_read_base',
		0x20:'_IO_write_base',
		0x28:'_IO_write_ptr',
		0x30:'_IO_write_end',
		0x38:'_IO_buf_base',
		0x40:'_IO_buf_end',
		0x48:'_IO_save_base',
		0x50:'_IO_backup_base',
		0x58:'_IO_save_end',
		0x60:'_markers',
		0x68:'_chain',
		0x70:'_fileno',
		0x74:'_flags2',
		0x78:'_old_offset',
		0x80:'_cur_column',
		0x82:'_vtable_offset',
		0x83:'_shortbuf',
		0x88:'_lock',
		0x90:'_offset',
		0x98:'_codecvt',
		0xa0:'_wide_data',
		0xa8:'_freeres_list',
		0xb0:'_freeres_buf',
		0xb8:'__pad5',
		0xc0:'_mode',
		0xc4:'_unused2',
		0xd8:'vtable'
	}
}


class IO_FILE_plus_struct(dict):
	arch = None
	endian = None
	fake_file = None
	size  = 0
	FILE_struct = []
	

	@LocalContext
	def __init__(self):
		self.arch = context.arch
		self.endian = context.endian

		if self.arch != 'i386' and self.arch != 'amd64':
			log.error('architecture not supported!')
		success('arch: '+str(self.arch))

		self.FILE_struct = [_IO_FILE_plus[self.arch][i] for i  in sorted(_IO_FILE_plus[self.arch].keys())]
		self.update({r:0 for r in self.FILE_struct})
		self.size = _IO_FILE_plus_size[self.arch]
		

	def __setitem__(self, item, value):
		if item not in self.FILE_struct:
			log.error("Unknown item %r (not in %r)" % (item, self.FILE_struct))
		super(IO_FILE_plus_struct, self).__setitem__(item, value)

	def __setattr__(self, attr, value):
		if attr in IO_FILE_plus_struct.__dict__:
			super(IO_FILE_plus_struct, self).__setattr__(attr, value)
		else:
			self[attr]=value

	def __getattr__(self, attr):
		return self[attr]

	def __str__(self):
		fake_file = ""
		with context.local(arch=self.arch):
			for item_offset in sorted(self.item_offset):
				if len(fake_file) < item_offset:
					fake_file += "\x00"*(item_offset - len(fake_file))
				fake_file += pack(self[_IO_FILE_plus[self.arch][item_offset]],word_size='all')
			fake_file += "\x00"*(self.size - len(fake_file))
		return fake_file

	@property
	def item_offset(self):
		return _IO_FILE_plus[self.arch].keys()