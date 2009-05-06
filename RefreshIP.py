#!/usr/bin/env python
# -*- coding: utf-8 -*-

import dbus
SystemBus = dbus.SystemBus()

# 查找网卡设备
oNetworkManager = SystemBus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
DeviceList = dbus.Interface(oNetworkManager, 'org.freedesktop.NetworkManager').GetDevices()
for device in DeviceList:
	oDevice = SystemBus.get_object('org.freedesktop.Hal', device)
	DeviceName = dbus.Interface(oDevice, 'org.freedesktop.Hal.Device').GetPropertyString('net.interface')
	if DeviceName == 'eth0':
		break

# 查找连接
oNetworkManagerSystemSettings = SystemBus.get_object('org.freedesktop.NetworkManagerSystemSettings', '/org/freedesktop/NetworkManagerSettings')
ConnnectionList = dbus.Interface(oNetworkManagerSystemSettings, 'org.freedesktop.NetworkManagerSettings').ListConnections()
for connection in ConnnectionList:
	oConnection = SystemBus.get_object('org.freedesktop.NetworkManagerSystemSettings', connection)
	settings = dbus.Interface(oConnection, 'org.freedesktop.NetworkManagerSettings.Connection').GetSettings()
	ConnectionID = settings.get('connection').get('id')
	if ConnectionID == 'System eth0' or ConnectionID == 'Auto eth0':
		break

# 激活网络接口
dbus.Interface(oNetworkManager, 'org.freedesktop.NetworkManager').ActivateConnection('org.freedesktop.NetworkManagerSystemSettings', connection, device, '/')

# 输出调试信息
DEBUG_MODE = 1
if DEBUG_MODE:
	print 'Network Connetion "' + ConnectionID + '":\t' + connection
	print 'Network interface "' + DeviceName + '":\t\t' + device

