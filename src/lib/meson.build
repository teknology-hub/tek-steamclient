# Using paths relative to root due to library object being created in the main
#    meson.build
lib_src = [
  'src/lib/cm_auth.cpp',
  'src/lib/cm_core.cpp',
  'src/lib/cm_pics.cpp',
  'src/lib/cm_sign_in.cpp',
  'src/lib/cm_steampipe.cpp',
  'src/lib/cm_workshop.cpp',
  'src/lib/error_msgs.c',
  'src/lib/lib_ctx.cpp',
  'src/lib' / (is_windows ? 'os_windows.c' : 'os_linux.c'),
  'src/lib/utils.c'
]
if get_option('s3_client')
  lib_src += 'src/lib/s3c.cpp'
endif # get_option('s3_client')
if get_option('content')
  lib_src += [
    'src/lib/depot_delta_compute.cpp',
    'src/lib/depot_delta.c',
    'src/lib/depot_manifest.c',
    'src/lib/depot_parse.cpp',
    'src/lib/depot_patch.c',
    'src/lib/verification_cache.c'
  ]
endif # get_option('content')
if get_option('steampipe')
  lib_src += 'src/lib/sp.c'
endif # get_option('steampipe')
if get_option('app_manager')
  lib_src += [
    'src/lib/am_cm.c',
    'src/lib/am_core.c',
    'src/lib/am_job.c',
    'src/lib/am_job_delete.c',
    'src/lib/am_job_download.c',
    'src/lib/am_job_install.c',
    'src/lib/am_job_patch.c',
    'src/lib/am_job_verify.c',
    'src/lib/am_vdf.cpp'
  ]
endif # get_option('app_manager')
