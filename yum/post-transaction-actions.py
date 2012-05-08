# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

# Copyright 2008 Red Hat, Inc
# written by Seth Vidal <skvidal@fedoraproject.org>

"""
This plugin runs actions following the transaction based on the content of
the transaction.
"""


from yum.plugins import TYPE_CORE
from yum.constants import *
import yum.misc
from yum.parser import varReplace
from yum.packages import parsePackages
import fnmatch
import re
import os
import glob
import shlex

requires_api_version = '2.4'
plugin_type = (TYPE_CORE,)

_just_installed = {} # pkgtup = po

def parse_actions(ddir, conduit):
    """read in .action files from ddir path. 
       store content in a list of tuples"""
    action_tuples = [] # (action key, action_state, shell command)
    action_file_list = []
    if os.access(ddir, os.R_OK): 
        action_file_list.extend(glob.glob(ddir + "*.action"))

    if action_file_list:
        for f in action_file_list:
            for line in open(f).readlines():
                line = line.strip()
                if line and line[0] != "#":
                    try:
                        (a_key, a_state, a_command) = line.split(':')
                    except ValueError,e:
                        conduit.error(2,'Bad Action Line: %s' % line)
                        continue
                    else:
                        action_tuples.append((a_key, a_state, a_command))

    return action_tuples

def _get_installed_po(rpmdb, pkgtup):
    (n,a,e,v,r) = pkgtup
    if pkgtup in _just_installed:
        return _just_installed[pkgtup]
    return rpmdb.searchNevra(name=n, arch=a, epoch=e, ver=v, rel=r)[0]

def _convert_vars(txmbr, command):
    """converts %options on the command to their values from the package it
       is running it for: takes $name, $arch, $ver, $rel, $epoch, 
       $state, $repoid"""
    state_dict = { TS_INSTALL: 'install',
                   TS_TRUEINSTALL: 'install',
                   TS_OBSOLETING: 'obsoleting',
                   TS_UPDATE: 'updating',
                   TS_ERASE: 'remove',
                   TS_OBSOLETED: 'obsoleted',
                   TS_UPDATED: 'updated'}
    try:
        state = state_dict[txmbr.output_state]
    except KeyError:
        state = 'unknown - %s' % txmbr.output_state

    vardict = {'name': txmbr.name,
               'arch': txmbr.arch,
               'ver': txmbr.version,
               'rel': txmbr.release,
               'epoch': txmbr.epoch,
               'repoid': txmbr.repoid,
               'state':  state }

    result = varReplace(command, vardict)
    return result
            
def posttrans_hook(conduit):
    # we have provides/requires for everything
    # we do not have filelists for erasures
    # we have to fetch filelists for the package object for installs/updates
    action_dir = conduit.confString('main','actiondir','/etc/yum/post-actions/')
    action_tuples = parse_actions(action_dir, conduit)
    commands_to_run = {}
    ts = conduit.getTsInfo()
    rpmdb = conduit.getRpmDB()
    all = ts.getMembers()
    removes = ts.getMembersWithState(output_states=TS_REMOVE_STATES)
    installs = ts.getMembersWithState(output_states=TS_INSTALL_STATES)
    updates = ts.getMembersWithState(output_states=[TS_UPDATE, TS_OBSOLETING])

    for (a_k, a_s, a_c) in action_tuples:
        #print 'if %s in state %s the run %s' %( a_k, a_s, a_c)
        if a_s  == 'update':
            pkgset = updates
        elif a_s == 'install':
            pkgset = installs
        elif a_s == 'remove':
            pkgset = removes
        elif a_s == 'any':
            pkgset = all
        else:
            # no idea what this is skip it
            conduit.error(2,'whaa? %s' % a_s)
            continue

        if a_k.startswith('/'):
            if yum.misc.re_glob(a_k):
                restring = fnmatch.translate(a_k)
                c_string = re.compile(restring)

            for txmbr in pkgset:
                matched = False
                #print '%s - %s' % txmbr.name, txmbr.ts_state
                if txmbr.po.state in TS_INSTALL_STATES:
                    thispo = _get_installed_po(rpmdb, txmbr.pkgtup)
        
                if not yum.misc.re_glob(a_k):
                    if a_k in thispo.filelist + thispo.dirlist + thispo.ghostlist:
                        thiscommand = _convert_vars(txmbr, a_c)
                        commands_to_run[thiscommand] = 1
                        matched = True
                else:
                    for name in thispo.filelist + thispo.dirlist + thispo.ghostlist:
                        if c_string.match(name):
                            thiscommand = _convert_vars(txmbr, a_c)
                            commands_to_run[thiscommand] = 1
                            matched = True
                            break
                
                if matched:
                    break
            continue
        
        if a_k.find('/') == -1: # pkgspec
            pkgs = [ txmbr.po for txmbr in pkgset ]
            e,m,u = parsePackages(pkgs, [a_k])
            if not u:
                for pkg in e+m:
                    for txmbr in ts.getMembers(pkgtup=pkg.pkgtup):
                        thiscommand = _convert_vars(txmbr, a_c)
                        commands_to_run[thiscommand] = 1
            continue

    for comm in commands_to_run.keys():
        try:
            args = shlex.split(comm)
        except ValueError, e:
            conduit.error(2,"command was not parseable: %s" % comm)
            continue
        #try
        conduit.info(2,'Running post transaction command: %s' % comm)
        p = os.system(comm)
        #except?


