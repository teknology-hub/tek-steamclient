# Using paths relative to root due to executable object being created in the
#    main meson.build
cli_src = [
  'src/cli/args.c',
  'src/cli/cmd_parser.c',
  'src/cli/cmd_runner.c',
  'src/cli/main.c',
  'src/cli/print_err.c'
]
if is_windows
  cli_src += 'src/cli/os_windows.c'
elif is_macos
  cli_src += 'src/cli/os_macos.c'
else
  cli_src += 'src/cli/os_linux.c'
endif
if get_option('cli_dump')
  cli_src += 'src/cli/dump.c'
endif # get_option('cli_dump')
