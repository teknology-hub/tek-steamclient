lib_src = files(
  'cm_auth.cpp',
  'cm_core.cpp',
  'cm_pics.cpp',
  'cm_sign_in.cpp',
  'cm_steampipe.cpp',
  'cm_workshop.cpp',
  'error_msgs.c',
  'lib_ctx.cpp',
  'utils.c',
  'ws_conn.cpp'
)

if is_windows
  lib_src += files('os_windows.c')
elif is_macos
  lib_src += files('os_macos.c')
else
  lib_src += files('os_linux.c')
endif
if get_option('s3_client')
  lib_src += files('s3c.cpp')
endif # get_option('s3_client')
if mz_needed
  lib_src += files(mz_dep.name() == 'minizip-ng'
    ? 'zip_mzng.c' : 'zip_mz.c')
endif # mz_needed
if get_option('content')
  lib_src += files(
    'depot_delta_compute.cpp',
    'depot_delta.c',
    'depot_manifest.c',
    'depot_parse.cpp',
    'depot_patch.c',
    'verification_cache.c'
  )
endif # get_option('content')
if get_option('steampipe')
  lib_src += files('sp.c')
endif # get_option('steampipe')
if get_option('app_manager')
  lib_src += files(
    'am_cm.c',
    'am_core.c',
    'am_job.c',
    'am_job_delete.c',
    'am_job_download.c',
    'am_job_install.c',
    'am_job_patch.c',
    'am_job_verify.c',
    'am_vdf.cpp'
  )
endif # get_option('app_manager')
