import requests

CGI = """./squashfs-root/home/httpd/easymesh/api.cgi
./squashfs-root/home/httpd/expertconf/wol/iux.cgi
./squashfs-root/home/httpd/expertconf/gamingvpn/iux.cgi
./squashfs-root/home/httpd/expertconf/hostscan/iux.cgi
./squashfs-root/home/httpd/expertconf/vpn/iux.cgi
./squashfs-root/home/httpd/expertconf/ddns/iux.cgi
./squashfs-root/home/httpd/expertconf/advertise/iux.cgi
./squashfs-root/home/httpd/m_handler.cgi
./squashfs-root/home/httpd/menu/menupage/iux.cgi
./squashfs-root/home/httpd/easymeshconf/advancesetup/iux.cgi
./squashfs-root/home/httpd/192.168.0.1/m_handler.cgi
./squashfs-root/home/httpd/192.168.0.1/m_login.cgi
./squashfs-root/home/httpd/192.168.0.1/captcha.cgi
./squashfs-root/home/httpd/m_login.cgi
./squashfs-root/home/httpd/cgi/iux_set.cgi
./squashfs-root/home/httpd/cgi/iux_download.cgi
./squashfs-root/home/httpd/cgi/timepro.cgi
./squashfs-root/home/httpd/cgi/iux.cgi
./squashfs-root/home/httpd/cgi/iux_get.cgi
./squashfs-root/home/httpd/cgi/upgrade.cgi
./squashfs-root/home/httpd/cgi/service.cgi
./squashfs-root/home/httpd/captcha.cgi
./squashfs-root/home/httpd/nasconf/basic/iux.cgi
./squashfs-root/home/httpd/netinfo/dhcpd/iux.cgi
./squashfs-root/home/httpd/netinfo/waninfo/iux.cgi
./squashfs-root/home/httpd/netinfo/laninfo/iux.cgi
./squashfs-root/home/httpd/vpnconf/filterrule/iux.cgi
./squashfs-root/home/httpd/vpnconf/vpncli/iux.cgi
./squashfs-root/home/httpd/natrouterconf/portforward/iux.cgi
./squashfs-root/home/httpd/natrouterconf/router/iux.cgi
./squashfs-root/home/httpd/natrouterconf/misc/iux.cgi
./squashfs-root/home/httpd/wirelessconf/easymesh/iux.cgi
./squashfs-root/home/httpd/wirelessconf/basicsetup/iux.cgi
./squashfs-root/home/httpd/wirelessconf/macauth/iux.cgi
./squashfs-root/home/httpd/wirelessconf/advancesetup/iux.cgi
./squashfs-root/home/httpd/basicapp/service/iux.cgi
./squashfs-root/home/httpd/firewallconf/accesslist/iux.cgi
./squashfs-root/home/httpd/firewallconf/firewall/iux.cgi
./squashfs-root/home/httpd/sysconf/snmp/iux.cgi
./squashfs-root/home/httpd/sysconf/syslog/iux.cgi
./squashfs-root/home/httpd/sysconf/login/iux.cgi
./squashfs-root/home/httpd/sysconf/info/iux.cgi
./squashfs-root/home/httpd/sysconf/swupgrade/iux.cgi
./squashfs-root/home/httpd/sysconf/misc/iux.cgi
./squashfs-root/home/httpd/trafficconf/linksetup/iux.cgi
./squashfs-root/home/httpd/trafficconf/connctrl/iux.cgi
./squashfs-root/home/httpd/trafficconf/conninfo/iux.cgi
./squashfs-root/home/httpd/trafficconf/qos/iux.cgi
./squashfs-root/home/httpd/trafficconf/switch/iux.cgi
./squashfs-root/cgibin/login_session.cgi
./squashfs-root/cgibin/download.cgi
./squashfs-root/cgibin/wireless_apply.cgi
./squashfs-root/cgibin/net_apply.cgi
./squashfs-root/cgibin/sys_apply.cgi
./squashfs-root/cgibin/d.cgi
./squashfs-root/cgibin/captcha.cgi
./squashfs-root/cgibin/timepro.cgi
./squashfs-root/cgibin/mesh.cgi
./squashfs-root/cgibin/login.cgi
./squashfs-root/cgibin/login_handler.cgi
./squashfs-root/cgibin/download_portforward.cgi
./squashfs-root/cgibin/info.cgi
./squashfs-root/cgibin/download_easymesh.cgi
./squashfs-root/cgibin/txbf.cgi
./squashfs-root/cgibin/download_firewall.cgi
./squashfs-root/cgibin/upgrade.cgi
./squashfs-root/cgibin/login-cgi/hostinfo.cgi
./squashfs-root/cgibin/login-cgi/login.cgi
./squashfs-root/cgibin/login-cgi/hostinfo2.cgi
./squashfs-root/cgibin/login-cgi/urlredir.cgi
./squashfs-root/cgibin/m.cgi
./squashfs-root/cgibin/txbf_act.cgi
./squashfs-root/cgibin/ddns/ddns_apply.cgi
./squashfs-root/cgibin/wol_apply.cgi"""

for l in CGI.splitlines():
    s = l.split('./squashfs-root/home/httpd')
    if len(s) == 2:
        path = s[1]

    r = requests.get('http://143.248.55.134:33357/%s' % path,
            headers={'referer': 'http://143.248.55.134:33357'})
    if r.status_code == 200:
        print(path)
