#!/usr/bin/env python
# -*- coding: utf-8 -*-

import dbus
SystemBus = dbus.SystemBus()

# 查找网卡设备
# (查找对应eth0的HAL设备名)
oNetworkManager = SystemBus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
szDeviceList = dbus.Interface(oNetworkManager, 'org.freedesktop.NetworkManager').GetDevices()
for szDevice in szDeviceList:
	oDevice = SystemBus.get_object('org.freedesktop.Hal', szDevice)
	szNetworkInterface = dbus.Interface(oDevice, 'org.freedesktop.Hal.Device').GetPropertyString('net.interface')
	if szNetworkInterface == 'eth0':
		break

# 查找连接
# (查找ID为"System eth0"或"Auto eth0"的连接)
oNetworkManagerSystemSettings = SystemBus.get_object('org.freedesktop.NetworkManagerSystemSettings', '/org/freedesktop/NetworkManagerSettings')
szConnnectionList = dbus.Interface(oNetworkManagerSystemSettings, 'org.freedesktop.NetworkManagerSettings').ListConnections()
for szConnection in szConnnectionList:
	oConnection = SystemBus.get_object('org.freedesktop.NetworkManagerSystemSettings', szConnection)
	szConnectionID = dbus.Interface(oConnection, 'org.freedesktop.NetworkManagerSettings.Connection').GetSettings().get('connection').get('id')
	if szConnectionID == 'System eth0' or szConnectionID == 'Auto eth0':
		break

# 输出调试信息
PRINT_DEBUG_MESSAGES = 1
if PRINT_DEBUG_MESSAGES:
	print '<debug_msg from="' + __file__ + '" func="' + __name__ + '">'
	print '  Hal Device: ' + szDevice
	print '    net.interface = "' + szNetworkInterface + '"'
	print '  NetworkManager Connection: ' + szConnection
	print '    connection.id = "' + szConnectionID + '"'

# 激活网络连接
szActivated = dbus.Interface(oNetworkManager, 'org.freedesktop.NetworkManager').ActivateConnection('org.freedesktop.NetworkManagerSystemSettings', szConnection, szDevice, '/')

# 检查ActivateConnection()的返回值
if PRINT_DEBUG_MESSAGES:
	print '  Activated Connection: ' + szActivated
	print '</debug_msg>'

