cli_src = files(
  'args.c',
  'cmd_parser.c',
  'cmd_runner.c',
  'main.c',
  'print_err.c'
)
if is_windows
  cli_src += files('os_windows.c')
elif is_macos
  cli_src += files('os_macos.c')
else
  cli_src += files('os_linux.c')
endif
if get_option('cli_dump')
  cli_src += files('dump.c')
endif # get_option('cli_dump')
