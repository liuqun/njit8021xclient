#!/usr/bin/env python
# -*- coding: utf-8 -*-

import dbus
SystemBus = dbus.SystemBus()

# 查找网卡接口
oNetworkManager = SystemBus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
szDeviceList = dbus.Interface(oNetworkManager, 'org.freedesktop.NetworkManager').GetDevices()
for szDevice in szDeviceList:
	oDevice = SystemBus.get_object('org.freedesktop.Hal', szDevice)
	szNetworkInterface = dbus.Interface(oDevice, 'org.freedesktop.Hal.Device').GetPropertyString('net.interface')
	if szNetworkInterface == 'eth0':
		break

# 查找连接
oNetworkManagerSystemSettings = SystemBus.get_object('org.freedesktop.NetworkManagerSystemSettings', '/org/freedesktop/NetworkManagerSettings')
szConnnectionList = dbus.Interface(oNetworkManagerSystemSettings, 'org.freedesktop.NetworkManagerSettings').ListConnections()
for szConnection in szConnnectionList:
	oConnection = SystemBus.get_object('org.freedesktop.NetworkManagerSystemSettings', szConnection)
	szConnectionID = dbus.Interface(oConnection, 'org.freedesktop.NetworkManagerSettings.Connection').GetSettings().get('connection').get('id')
	if szConnectionID == 'System eth0' or szConnectionID == 'Auto eth0':
		break

# 激活网络接口
dbus.Interface(oNetworkManager, 'org.freedesktop.NetworkManager').ActivateConnection('org.freedesktop.NetworkManagerSystemSettings', szConnection, szDevice, '/')

# 输出调试信息
PRINT_DEBUG_MESSAGES = 1
if PRINT_DEBUG_MESSAGES:
	print 'Activate network connetion "' + szConnectionID + '"'
	print '\t' + szConnection
	print 'Using network interface "' + szNetworkInterface + '"'
	print '\t' + szDevice

