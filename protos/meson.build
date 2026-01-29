proto_src = []
subdir('tek/steamclient/cm')
if get_option('content')
  subdir('tek/steamclient/content')
endif # get_option('content')

lib_src += generator(
  find_program('protoc'),
  arguments: [
    '--proto_path=@SOURCE_DIR@/protos', '--cpp_out=@BUILD_DIR@', '@INPUT@'
  ],
  output: ['@BASENAME@.pb.cc', '@BASENAME@.pb.h']
).process(proto_src, preserve_path_from: meson.current_source_dir())
