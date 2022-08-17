# ospd-scans

Is a small utility to make direct OSP commands easier to handle.

To function it needs to have
- the vt feed
- scan-configs from data-object feed
- as well as an running OSPD in either TCP or UNIX mode

It reads the scan-config (in our lingo from now on policy) and creates an OSP start scan command and sends it to OSPD.

## Usage

```
Usage of bin/ospd-scans:
  -a string
    	(optional, when set it will NOT use unix socket but TCP) a target address (e.g. 10.42.0.81:4242)
  -alive-method int
    	which alive method to use; 1. bit is for ICMP, 2. bit is for TCPSYN, 3. bit is for TCPACK, 4. bit is for ARP and 5. bit is to consider alive. (default 15)
  -cert-path string
    	(only require when port is set ) path to the certificate used by ospd.
  -certkey-path string
    	(only required when port is set) path to certificate key used by ospd.
  -cmd string
    	Can either be start,get,start-finish.
  -host string
    	host to scan
  -id string
    	id of a scan
  -oid string
    	comma separated list of oid of a plugin to execute
  -password string
    	password of user (when using credentials)
  -policies string
    	comma separated list of policies.
  -policy-path string
    	path to policies. (default "/usr/local/src/policies")
  -ports string
    	comma separated list of ports. (default "22,80,443,8080,513")
  -u string
    	path the ospd unix socket (default "/run/ospd/ospd-openvas.sock")
  -user string
    	user of host (when using credentials)
  -v	Enables or disables verbose.
  -vt-dir string
    	A path to existing plugins. (default "/var/lib/openvas/plugins")
```
