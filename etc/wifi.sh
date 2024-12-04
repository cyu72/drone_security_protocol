#!/bin/bash
# This script disables ad hoc networking and restores normal WiFi connectivity

echo "Stopping ad hoc network configuration..."
sudo ifconfig wlan0 down
sudo systemctl start wpa_supplicant.service

echo "Backing up ad hoc configuration file..."
if [ -f /etc/network/interfaces.d/adhoc.conf ]; then
    sudo mv /etc/network/interfaces.d/adhoc.conf /etc/network/interfaces.d/adhoc.conf.backup
    echo "Ad hoc configuration backed up"
else
    echo "No ad hoc configuration file found"
fi

echo "Stopping DHCP service if running..."
if systemctl is-active --quiet dnsmasq; then
    sudo systemctl stop dnsmasq
    echo "DHCP service stopped"
else
    echo "DHCP service not running"
fi

echo "Restoring normal WiFi configuration..."
sudo wpa_cli reconfigure

echo "Restarting networking service..."
sudo systemctl restart networking

echo "Bringing wireless interface back up..."
sudo ifconfig wlan0 up

echo "Network configuration reset completed."
echo "If WiFi doesn't connect automatically, you may need to reboot with: sudo reboot"
