#!/usr/bin/env python

import sys

sys.path.append('/usr/lib/vmware-vmafd/lib64')

import vmafd

def getMachineAccountCredentials():
    client = vmafd.client('localhost')
    username = client.GetMachineName()
    password = client.GetMachinePassword()
    return (username, password)

if __name__ == "__main__":
    print(getMachineAccountCredentials())
