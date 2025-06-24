hdrs = [
  'tek-steamclient/base.h',
  'tek-steamclient/cm.h',
  'tek-steamclient/error.h',
  'tek-steamclient/os.h'
]
if get_option('s3_client')
  hdrs += 'tek-steamclient/s3c.h'
endif # get_option('s3_client')
if get_option('content') or get_option('steampipe')
  hdrs += 'tek-steamclient/content.h'
endif # get_option('content') or get_option('steampipe')
if get_option('steampipe')
  hdrs += 'tek-steamclient/sp.h'
endif # get_option('steampipe')
if get_option('app_manager')
  hdrs += 'tek-steamclient/am.h'
endif # get_option('steampipe')

install_headers(hdrs, subdir: 'tek-steamclient')
