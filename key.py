# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         key
# Purpose:      Basic licensce key control
#
# Author:       ThreatPipes
#
# Created:      23/07/2019
# Copyright:    (c) ThreatPipes 2019
# License:      GPL
# -----------------------------------------------------------------

import hashlib

def check_key(lickey):
    if lickey:
        try:
            parts = lickey.split('-')
            if len(lickey) == 23 and 'P' in parts[1] and 'S' in parts[2] and 'T' in parts[3]:
                if lickey[20] == '3' and lickey[21] == '4':
                    return 'Not extended'
                else:
                    return 'Activated'
            else:
                return 'Invalid key'
        except:
            return 'Error'
    else:
        return 'Empty'
