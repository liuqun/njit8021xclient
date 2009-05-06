#!/bin/sh

echo Refreshing IP address...

dbus-send --system --type=method_call		\
          --dest=org.freedesktop.NetworkManager	\
                /org/freedesktop/NetworkManager	\
                 org.freedesktop.NetworkManager.ActivateConnection      \
            string:"org.freedesktop.NetworkManagerSystemSettings"       \
            objpath:/org/freedesktop/NetworkManagerSettings/0           \
            objpath:/org/freedesktop/Hal/devices/net_00_16_36_52_53_12  \
            objpath:/

