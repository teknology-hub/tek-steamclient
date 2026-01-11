project(
  'tek-steamclient',
  'c', 'cpp',
  version: files('meson.version'), meson_version: '>=1.3.2',
  license: 'GPL-3.0-or-later', license_files: 'COPYING',
  default_options: {
    'cpp_std': 'gnu++23',
    'warning_level': '3'
  }
)
if get_option('app_manager') and (
  not get_option('content') or
  not get_option('steampipe'))
  error('"app_manager" option requires "content" and "steampipe" to be enabled as well')
endif
if get_option('cli_dump') and not get_option('app_manager') 
  error('"cli_dump" option requires "app_manager" to be enabled as well')
endif
add_project_arguments('-DTEK_SC_IMPL', language: ['c', 'cpp'])
is_windows = host_machine.system() == 'windows'
is_macos = host_machine.system() == 'darwin'
if is_windows
  add_project_arguments('-DUNICODE', '-D_UNICODE', language: ['c', 'cpp'])
  add_project_link_arguments('-municode', language: ['c', 'cpp'])
  winmod = import('windows')
  # Make file version for .rc files
  rc_version = meson.project_version().replace('.', ',')
  if rc_version.contains('-')
    rc_version = rc_version.split('-')[0]
  endif
  num_elems = rc_version.split(',').length()
  if num_elems == 2
    rc_version += ',0,0'
  endif
  if num_elems == 3
    rc_version += ',0'
  endif
else # is_windows
  add_project_arguments('-D_GNU_SOURCE', language: ['c', 'cpp'])
endif # is_windows else
compiler = meson.get_compiler('c')
# -Wno-attributes: Project code uses many attributes that are supported only by
#    specific compilers or even specific compiler versions
# -Wno-invalid-offsetof: There's no good enough alternative to this trick yet
# -Wno-nullability-extension: Fallbacks for these attributes are provided by
#    base.h anyway
# -Wno-pointer-arith: provided by GNU extensions (gcc)
# -Wno-gnu-binary-literal: provided by GNU extensions (clang)
# -Wno-gnu-pointer-arith: provided by GNU extensions (clang)
add_project_arguments(
  compiler.get_supported_arguments(
    '-Wno-attributes', '-Wno-invalid-offsetof','-Wno-nullability-extension',
    '-Wno-pointer-arith', '-Wno-gnu-binary-literal', '-Wno-gnu-pointer-arith'
  ),
  language: ['c', 'cpp']
)
if is_macos
  add_project_arguments('-mmacosx-version-min=13.3', language: ['c', 'cpp'])
endif
if is_windows
  # These libraries aren't linked automatically in MSYS2 environment
  win_deps = [
    compiler.find_library('ntdll'),
    compiler.find_library('synchronization')
  ]
  if (get_option('gettext'))
    win_deps += [
      dependency('iconv'),
      compiler.find_library('intl')
    ]
  endif # get_option('gettext')
endif # is_windows
zlib_dep = dependency('zlib-ng', required: get_option('zlib_ng'))
if not zlib_dep.found()
  zlib_dep = dependency('zlib')
endif # not zlib_dep.found()
mz_needed = get_option('content') or get_option('steampipe')
if mz_needed
  mz_dep = dependency('minizip-ng', required: get_option('minizip_ng'))
  if not mz_dep.found()
    mz_dep = dependency('minizip')
  endif # not mz_dep.found()
endif # mz_needed
liburing_valid = get_option('app_manager') and not is_windows
if liburing_valid
  liburing_dep = dependency('liburing', required: get_option('io_uring'))
endif # liburing_valid
soversion = meson.project_version().split('.')[0]
configure_file(
  output: 'config.h',
  configuration: {
    'TEK_SC_VERSION': '"' + meson.project_version() + '"',
    'TEK_SC_UA': '"tek-steamclient/' + meson.project_version() + '"',
    'TEK_SCB_SOVERSION': f'"@soversion@"',
    'TEK_SCB_ZNG': zlib_dep.name() == 'zlib-ng',
    'TEK_SCB_GETTEXT': get_option('gettext'),
    'TEK_SCB_S3C': get_option('s3_client'),
    'TEK_SCB_CONTENT': get_option('content'),
    'TEK_SCB_SP': get_option('steampipe'),
    'TEK_SCB_CHUNKS_PER_SRV': get_option('chunks_per_srv'),
    'TEK_SCB_AM': get_option('app_manager'),
    'TEK_SCB_IO_URING': liburing_valid and liburing_dep.found(),
    'TEK_SCB_CLI_DUMP': get_option('cli_dump')
  }
)
subdir('include')
common_includes = include_directories('include', 'src')
override_options = {
  # Meson supports c23/gnu23 only since 1.4.0
  'c_std': meson.version().version_compare('<1.4.0') ? 'gnu2x' : 'gnu23'
}

if get_option('gettext')
  subdir('po')
endif # get_option('gettext')

### libtek-steamclient
lib_args = ['-DTEK_SC_EXPORT']
if zlib_dep.name() == 'zlib'
  lib_args += ['-DZLIB_CONST']
endif # zlib_dep.name() == 'zlib'
lib_deps = [
  dependency('RapidJSON'),
  dependency('libcrypto'),
  dependency('libcurl'),
  dependency('libuv'),
  dependency('protobuf-lite'),
  dependency('sqlite3'),
  dependency('threads'),
  zlib_dep
]
if mz_needed
  lib_deps += mz_dep
endif # mz_needed
if get_option('steampipe')
  libzstd_dep = dependency('libzstd')
  lib_deps += [
    dependency('liblzma'),
    libzstd_dep
  ]
endif # get_option('steampipe')
if get_option('app_manager')
  lib_deps += subproject(
    'ValveFileVDF'
  ).get_variable('valve_file_vdf_dep')
  if not is_windows and liburing_dep.found()
    lib_deps += liburing_dep
  endif # not is_windows and liburing_dep.found()
endif # get_option('app_manager')
subdir('src/lib')
if is_windows
  lib_deps += win_deps
  # Build localization .mo files for including as resources
  loc_list = []
  res_id = 1001
  loc_defs = []
  loc_tgts = []
  if get_option('gettext')
    foreach lang : import('fs').read('po/LINGUAS').strip().split()
      loc_list += f'L"@lang@\0",'
      loc_defs += f'@res_id@ RCDATA "@lang@.mo"'
      res_id += 1
      loc_tgts += custom_target(
        f'loc-@lang@',
        input: f'po/@lang@.po',
        output: f'@lang@.mo',
        command: [find_program('msgfmt'), '@INPUT@', '-o', '@OUTPUT@']
      )
    endforeach
  endif # getoption('gettext')
  if get_option('default_library') != 'static'
    lib_src += winmod.compile_resources(
      configure_file(
        input: 'res/tek-steamclient.rc.in',
        output: 'tek-steamclient.rc',
        configuration: {
          'file_version': rc_version,
          'pretty_version': meson.project_version(),
          'soversion': soversion,
          'loc_list': '\n'.join(loc_list),
          'loc_defs': '\n'.join(loc_defs)
        }
      ),
      depends: loc_tgts
    )
  endif # get_option('default_library') != 'static'
endif # is_windows
subdir('protos')
libtek_steamclient = library(
  'tek-steamclient',
  lib_src,
  c_args: lib_args,
  cpp_args: lib_args,
  c_static_args: '-DTEK_SC_STATIC',
  cpp_static_args: '-DTEK_SC_STATIC',
  dependencies: lib_deps,
  gnu_symbol_visibility: 'hidden',
  include_directories: common_includes,
  install: true,
  override_options: override_options,
  soversion: soversion
)
static_arg_arr = (
  get_option('default_library') == 'static'
  or (
    get_option('default_library') == 'both'
    and meson.version().version_compare('>=1.6.0')
    and get_option('default_both_libraries') == 'static'
  )
) ? '-DTEK_SC_STATIC' : []
import('pkgconfig').generate(
  libtek_steamclient,
  description: 'An open-source partial Steam client implementation',
  extra_cflags: static_arg_arr,
  url: 'https://github.com/teknology-hub/tek-steamclient'
)

### tek-sc-cli
cli_deps = []
subdir('src/cli')
if is_windows
  cli_deps += win_deps
  configure_file(
    input: 'res/tek-sc-cli.manifest.in',
    output: 'tek-sc-cli.manifest',
    configuration: {'version': rc_version.replace(',', '.')}
  )
  configure_file(
    input: 'res/tek-steamclient.ico',
    output: 'tek-steamclient.ico',
    copy: true
  )
  cli_src += winmod.compile_resources(
    configure_file(
      input: 'res/tek-sc-cli.rc.in',
      output: 'tek-sc-cli.rc',
      configuration: {
        'file_version': rc_version,
        'pretty_version': meson.project_version(),
        'loc_list': '\n'.join(loc_list),
        'loc_defs': '\n'.join(loc_defs)
      }
    ),
    args: static_arg_arr,
    depends: loc_tgts
  )
endif # is_windows
if get_option('cli_dump')
  cli_deps += libzstd_dep
endif # get_option('cli_dump')
tek_sc_cli = executable(
  'tek-sc-cli',
  cli_src,
  build_by_default: get_option('cli'),
  c_args: static_arg_arr,
  cpp_args: static_arg_arr,
  dependencies: cli_deps,
  gnu_symbol_visibility: 'hidden',
  include_directories: common_includes,
  install: get_option('cli'),
  link_with: libtek_steamclient,
  override_options: override_options
)
