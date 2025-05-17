project('dpdk_ping', 'c')

pkgconfig = find_program('pkg-config')
cflags_cmd = run_command(pkgconfig, '--cflags', 'libdpdk', check: true)
ldflags_cmd = run_command(pkgconfig, '--libs', 'libdpdk', check: true)

cflags = cflags_cmd.stdout().split()
ldflags = ldflags_cmd.stdout().split()

ldflags += ['-lm', '-lpthread']

sources = files('main.c', 'dpdk.c')
executable('dpdk-ping', sources, c_args: cflags, link_args: ldflags)

ldflags += ['-lpcap']

sources = files('dpdk-pcapreply.c', 'dpdk.c')
executable('dpdk-pcapreply', sources, c_args: cflags, link_args: ldflags)
