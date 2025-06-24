i18n = import('i18n')
project_name = meson.project_name()
add_project_arguments(f'-DGETTEXT_PACKAGE=@project_name@', language: ['c', 'cpp'])
i18n.gettext(project_name, args: '-ktsc_gettext')
