# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

from waflib import Configure, Utils, Logs, Context
import os

VERSION = "0.1"
APPNAME = "signed-data1"



def options(opt):
    # gnu_dirs: Sets various standard variables such as INCLUDEDIR
    opt.load(['compiler_cxx', 'gnu_dirs'])

    opt.load(['default-compiler-flags', 'boost'],
              tooldir=['.waf-tools'])


def configure(conf):
    conf.load(['compiler_cxx', 'default-compiler-flags', 'boost', 'gnu_dirs'])

    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', mandatory=True)

    boost_libs = 'system iostreams random thread filesystem'

    conf.check_boost(lib=boost_libs)

    if 'PKG_CONFIG_PATH' not in os.environ:
        os.environ['PKG_CONFIG_PATH'] = ':'.join([
           '/usr/local/lib/pkgconfig',
           '/opt/local/lib/pkgconfig'])

    conf.check_cfg (package='libmacaroons', args=['--cflags', '--libs'],
                   uselib_store='macaroons', mandatory=True)

    conf.check_cfg(package='NDNMacaroon', args=['NDNMacaroon >= 0.1', '--cflags', '--libs'],
                    uselib_store='NDNMACAROON', mandatory=True)

    conf.write_config_header('config.h')

def build (bld):
    bld.recurse("src")

