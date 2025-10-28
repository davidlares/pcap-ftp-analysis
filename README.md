## Analyzing PCAP FTP files

The following script is intended to read, evaluate, and analyze packet capture files from a security perspective using Python. In a more specific way, looking for unusual network patterns.

The `malicious.py` is the file responsible for handling CLI arguments, looking for FTP network activity, and tracking the authentication attempts based on the status code present in every packet of the `pcap` file.

This basically tries to emulate a simple `Wireshark's Follow TCP Stream or HTTP stream` alike, but in a programmatic way. The main protagonist is the `Scapy` library (check the `requirements.txt`). This awesome tool is a generic-purpose sniffer/packet crafter that can interact with network packets on a deep level and also detail packet components based on a known `pcap` network file. (actually, Scapy is more than this)

The whole criteria are based on whether it is an anomaly or a malicious attack. This is up to you; if we have 500 wrong attempts but success, then I'm pretty sure we have in front of a brute-force attack.

## Run

Simply run: `python malicious.py /path/to/attacks.pcap -i [IP]`

The `IP` argument must match or be present inside the `pcap` file. The example works well with the local IP `192.168.37.131`

## Output

The output looks like this:

```
[+] Starting to read packets from file with filter "tcp port 21 and host 192.168.37.131".
reading from file pcap-files/attacks.pcap, link-type EN10MB (Ethernet)
Checking for brute force/dictionary attacks.
{
  "192.168.37.128": {
    "failed": 257,
    "successful": 1,
    "attacker": true,
    "message": "[!] ALERT: Likely attacker with 1 successful login detected!"
  }
}
```

## Credits
[David Lares S](https://davidlares.com)

## License
[MIT](https://opensource.org/licenses/MIT)
