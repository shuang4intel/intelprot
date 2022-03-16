#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modify spdm-emu source code
C:\shuang4\Work\_PFR\spdm-emu
"""
import os, sys
import argparse

#srcpath = r'C:\shuang4\Work\_PFR\spdm-emu'
f1 = os.path.join('spdm_emu', 'spdm_emu_common', 'command.h')
f1_line_cur = '#define DEFAULT_SPDM_PLATFORM_PORT  2323'
f1_line_new = '#define DEFAULT_SPDM_PLATFORM_PORT  2323\n#define DEFAULT_SPDM_REQUESTER_PORT 2324\n#define DEFAULT_SPDM_RESPONDER_PORT 2325\n'

f2 = os.path.join('spdm_emu', 'spdm_requester_emu', 'spdm_requester_emu.c')
f2_line_cur = 'platform_client_routine(DEFAULT_SPDM_PLATFORM_PORT);'
f2_line_new = '    //platform_client_routine(DEFAULT_SPDM_PLATFORM_PORT);\n    platform_client_routine(DEFAULT_SPDM_REQUESTER_PORT);\n'

f3 = os.path.join('spdm_emu', 'spdm_responder_emu', 'spdm_responder_emu.c')
f3_line_cur = 'platform_server_routine(DEFAULT_SPDM_PLATFORM_PORT);'
f3_line_new = '    //platform_server_routine(DEFAULT_SPDM_PLATFORM_PORT);\n    platform_server_routine(DEFAULT_SPDM_RESPONDER_PORT);\n'

def replace_file_line(fname, cur_line, new_lines):
  """ replace file lines """
  with open(fname, 'r') as f:
    all_lines=f.readlines()
  lst_new = new_lines.split('\n')
  lst_A = [item.strip() for item in lst_new]
  lst_B = [item.strip() for item in all_lines]
  #print(lst_A)
  #print(lst_B)
  if any(item in lst_A for item in lst_B):
    print('-- no action on {}, already modified'.format(fname))
    return
  else:
    all_lines = [new_lines if item.strip() == cur_line else item for item in all_lines]
    with open(fname, 'w+') as f:
      f.writelines(all_lines)

def main(args):
  """ """
  parser = argparse.ArgumentParser(description="-- modify spdm-emu source utility")
  parser.add_argument('-p', '--spdm-emu-path', metavar="[spdm-emu path]", dest='srcpath', help='spdm-emu source file path')

  args = parser.parse_args(args)
  print('args:\n', args)

  global f1, f2, f3
  f1=os.path.join(args.srcpath, f1)
  f2=os.path.join(args.srcpath, f2)
  f3=os.path.join(args.srcpath, f3)
  replace_file_line(f1, f1_line_cur, f1_line_new)
  replace_file_line(f2, f2_line_cur, f2_line_new)
  replace_file_line(f3, f3_line_cur, f3_line_new)

if __name__ == '__main__':
  main(sys.argv[1:])




