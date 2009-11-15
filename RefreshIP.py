#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# 功能：
#   通过NetworkManager刷新IP地址激活默认的网络连接
# 局限性：
#   1、主函数main()中使用eth0作为默认网卡，有些情况可能需要手动修改为eth1等。
#   2、njit-client尚不支持无线网络，故此处已经跳过所有的无线网络配置
# 欢迎帮助我们改进这个Python脚本，来信请寄：
#   njit8201xclient@googlegroups.com
#   http://groups.google.com/group/njit8021xclient?hl=zh-CN
#

import dbus
from networkmanager import NetworkManager
from networkmanager.applet import NetworkManagerSettings, SYSTEM_SERVICE, USER_SERVICE
sysbus = dbus.SystemBus()
nm = NetworkManager()


def GetHalNetworkDeviceName(ethn):
	deviceList = dbus.Interface(nm, 'org.freedesktop.NetworkManager').GetDevices()
	for deviceName in deviceList:
		device = sysbus.get_object('org.freedesktop.Hal', deviceName)
		if dbus.Interface(device, 'org.freedesktop.Hal.Device').GetPropertyString('net.interface') == ethn:
			return deviceName
	return '' # When no HAL device matches ethn...



def GetActiveEthernetConnection(svc):
	activeConnections = map(lambda a: a['Connection'].object_path, nm['ActiveConnections'])
	try:
		connections = NetworkManagerSettings(svc).ListConnections()
	except dbus.exceptions.DBusException, e:
		print e
	for connection in connections:
	 	type = connection.GetSettings()['connection']['type']
		if (type=='802-3-ethernet') and (connection.object_path in activeConnections):
			return connection
	return '' # When no connection is found...



# 主函数
def main():
	# 查找对应网卡eth0的HAL设备名
	deviceName = GetHalNetworkDeviceName('eth0')
	# 查找当前配置的有线网络连接(优先查找用户自定义的网络连接)
	connection = GetActiveEthernetConnection(USER_SERVICE)
	if connection != '':
		try:	# 激活用户定义的网络连接
			dbus.Interface(nm, 'org.freedesktop.NetworkManager').ActivateConnection(USER_SERVICE, connection.object_path, deviceName, '/')
			print __file__ + ': 已激活网络连接“' + connection.GetSettings()['connection']['id'] + '”'
			return 0
		except dbus.exceptions.DBusException, e:
			print e
	# 用户没有自定义时使用系统默认的连接
	connection = GetActiveEthernetConnection(SYSTEM_SERVICE)
	if connection != '':
		try:	# 激活系统默认的网络连接(Fedora定义为"System eth0"，Ubuntu定义为"Auto eth0")
			dbus.Interface(nm, 'org.freedesktop.NetworkManager').ActivateConnection(SYSTEM_SERVICE, connection.object_path, deviceName, '/')
			print __file__ + ': 已激活默认网络连接“' + connection.GetSettings()['connection']['id'] + '”'
			return 0
		except dbus.exceptions.DBusException, e:
			print e
	print __file__ + ': Failed to refresh IP address'
	return -1



# 执行主函数
main()

