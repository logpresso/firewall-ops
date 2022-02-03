![Logpresso Logo](logo.png)

Logpresso FirewallOps is a single binary command-line tool for iptables and firewalld policy automation. It receives blocklist from Logpresso Watch and update firewall drop rule periodically.

## Requirement
* [Logpresso Watch](https://logpresso.watch) service user
* iptables or firewalld installation
  * iptables with ipset
  * firewalld
* Connectivity with [Logpresso Watch](https://logpresso.watch)
  * If you cannot connect to internet from server farm directly, use [Logpresso HTTP proxy](https://github.com/logpresso/http-proxy) for relay.

### Usage
```
Logpresso Firewall Ops 0.1.0 (2022-01-31)
Usage: logpresso-firewall-ops [start|install|uninstall]
  start
  install [api-key] [http-proxy ip:port]
  uninstall
```

### Getting Started

* Join Logpresso Watch and copy Blocklist API Key from Profile page.
* Install FirewallOps as systemd service.
  * `# ./logpresso-firewall-ops install YOUR_BLOCKLIST_API_KEY`
  * logpresso-firewall-ops.conf file will be created in the same directory which contains logpresso-firewall-ops binary.
  * FirewallOps uses `firewalld-cmd --state` to detect firewalld is running. If firewalld is not available, it fallback to iptables backend.
* Review logpresso-firewall-ops.conf configuration.
  * `[allowlist]` seciton contains default private network subnets to prevent accidental IP blocking like this:
    ```
    [allowlist]
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16
    ```
  * Add more IP addresses related to normal service operation.
* Start systemd service.
  * `# systemctl start logpresso-firewall-ops`
* Check service status
  * For systemd service - `# systemctl status logpresso-firewall-ops`
  * For iptables - `iptables -L -n`
    * `DROP       all  --  0.0.0.0/0            0.0.0.0/0            match-set logpresso-watch src`
    * To see ipset content - `# ipset save logpresso-watch`

### Uninstall
* Stop systemd service first.
  * `# systemctl stop logpresso-firewall-ops`
* Run FirewallOps with uninstall option.
  * '# ./logpresso-firewall-ops uninstall`
  * It will delete systemd file, config file, and reload systemd daemon.


### Contact
If you have any question or issue, create an issue in this repository.

