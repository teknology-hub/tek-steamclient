proto_src = [
  'tek/steamclient/cm/emsg.proto',
  'tek/steamclient/cm/message_header.proto',
  'tek/steamclient/cm/msg_payloads/auth_common.proto',
  'tek/steamclient/cm/msg_payloads/begin_auth_session_via_credentials.proto',
  'tek/steamclient/cm/msg_payloads/begin_auth_session_via_qr.proto',
  'tek/steamclient/cm/msg_payloads/generate_access_token_for_app.proto',
  'tek/steamclient/cm/msg_payloads/get_details.proto',
  'tek/steamclient/cm/msg_payloads/get_depot_decryption_key.proto',
  'tek/steamclient/cm/msg_payloads/get_depot_patch_info.proto',
  'tek/steamclient/cm/msg_payloads/get_manifest_request_code.proto',
  'tek/steamclient/cm/msg_payloads/get_password_rsa_public_key.proto',
  'tek/steamclient/cm/msg_payloads/get_servers_for_steampipe.proto',
  'tek/steamclient/cm/msg_payloads/heartbeat.proto',
  'tek/steamclient/cm/msg_payloads/hello.proto',
  'tek/steamclient/cm/msg_payloads/license_list.proto',
  'tek/steamclient/cm/msg_payloads/logoff.proto',
  'tek/steamclient/cm/msg_payloads/logon.proto',
  'tek/steamclient/cm/msg_payloads/multi.proto',
  'tek/steamclient/cm/msg_payloads/os_type.proto',
  'tek/steamclient/cm/msg_payloads/pics_access_token.proto',
  'tek/steamclient/cm/msg_payloads/pics_changes_since.proto',
  'tek/steamclient/cm/msg_payloads/pics_product_info.proto',
  'tek/steamclient/cm/msg_payloads/poll_auth_session_status.proto',
  'tek/steamclient/cm/msg_payloads/published_file_details.proto',
  'tek/steamclient/cm/msg_payloads/query_files.proto',
  'tek/steamclient/cm/msg_payloads/request_encrypted_app_ticket.proto',
  'tek/steamclient/cm/msg_payloads/update_auth_session_with_steam_guard_code.proto'
]
if get_option('content')
  proto_src += [
    'tek/steamclient/content/manifest_metadata.proto',
    'tek/steamclient/content/manifest_payload.proto',
    'tek/steamclient/content/patch_payload.proto'
  ]
endif # get_option('content')

lib_src += generator(
  find_program('protoc'),
  arguments: [
    '--proto_path=@SOURCE_DIR@/protos', '--cpp_out=@BUILD_DIR@', '@INPUT@'
  ],
  output: ['@BASENAME@.pb.cc', '@BASENAME@.pb.h']
).process(proto_src, preserve_path_from: meson.current_source_dir())
