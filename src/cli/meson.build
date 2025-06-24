# Using paths relative to root due to executable object being created in the
#    main meson.build
cli_src = [
  'src/cli/args.c',
  'src/cli/cmd_parser.c',
  'src/cli/cmd_runner.c',
  'src/cli/main.c',
  'src/cli' / (is_windows ? 'os_windows.c' : 'os_linux.c'),
  'src/cli/print_err.c'
]
if get_option('cli_dump')
  cli_src += 'src/cli/dump.c'
endif # get_option('cli_dump')
