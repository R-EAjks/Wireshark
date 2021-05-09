#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Based on suite_nameres.py
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Name resolution tests for diagnostic addresses'''

import os.path
import shutil
import subprocesstest
import fixtures

tf_str = { True: 'TRUE', False: 'FALSE' }

custom_profile_name = 'Custom Profile Diagnostic Addresses'

@fixtures.fixture
def diag_addr_env(test_env, program_path, conf_path):
    custom_profile_path = os.path.join(conf_path, 'profiles', custom_profile_name)
    os.makedirs(custom_profile_path)
    this_dir = os.path.dirname(__file__)
    hosts_path_pfx = os.path.join(this_dir, 'diagnostic_addresses.')
    shutil.copyfile(hosts_path_pfx + 'personal', os.path.join(conf_path, 'diagnostic_addresses'))
    shutil.copyfile(hosts_path_pfx + 'custom', os.path.join(custom_profile_path, 'diagnostic_addresses'))
    return test_env

@fixtures.fixture
def check_name_resolution_diag_addr(cmd_tshark, capture_file, diag_addr_env):
    def check_name_resolution_diag_addr_real(self, o_diag_name_res, custom_profile, grep_str, fail_on_match=False):
        tshark_cmd = (cmd_tshark,
            '-r', capture_file('doip.pcap.gz'),
            '-o', 'nameres.diag_addr_name: ' + tf_str[o_diag_name_res],
            '-V'
            )
        if custom_profile:
            tshark_cmd += ('-C', custom_profile_name)
        self.assertRun(tshark_cmd, env=diag_addr_env)
        if fail_on_match:
            self.assertFalse(self.grepOutput(grep_str))
        else:
            self.assertTrue(self.grepOutput(grep_str))
    return check_name_resolution_diag_addr_real


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_name_resolution_diag_addr(subprocesstest.SubprocessTestCase):

    def test_name_resolution_diag_addr_t_personal(self, check_name_resolution_diag_addr):
        '''Name resolution, personal profile.'''
        # nameres.diag_addr_name: True
        # Profile: Default
        check_name_resolution_diag_addr(self, True, False, 'ECU-personal')

    def test_name_resolution_diag_addr_t_custom(self, check_name_resolution_diag_addr):
        '''Name resolution, custom profile.'''
        # nameres.diag_addr_name: True
        # Profile: Custom
        check_name_resolution_diag_addr(self, True, True, 'ECU-custom')

    def test_name_resolution_diag_addr_f_personal(self, check_name_resolution_diag_addr):
        '''Name resolution, personal profile.'''
        # nameres.diag_addr_name: False
        # Profile: Default
        check_name_resolution_diag_addr(self, False, False, 'ECU-personal', True)

    def test_name_resolution_diag_addr_f_custom(self, check_name_resolution_diag_addr):
        '''Name resolution, custom profile.'''
        # nameres.diag_addr_name: False
        # Profile: Custom
        check_name_resolution_diag_addr(self, False, True, 'ECU-custom', True)
