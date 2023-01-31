from cx_Freeze import setup, Executable


build_exe_options = {
    'zip_include_packages': '*',
    'zip_exclude_packages': ['dnspooh'],
    'excludes': ['tkinter'],
    'include_msvcr': True,
}

setup(
    options={
        'build_exe': build_exe_options
    },
    executables=[
        Executable(
            "main.py", 
            target_name='dnspooh', 
            shortcut_name='Dnspooh',
            icon='webui/favicon.ico'
        )
    ]
)
