# CobaltSpam
Tool based on [CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser) from SentinelOne which can be used to spam a CobaltStrike server with fake beacons

![alt text](https://github.com/hariomenkel/CobaltSpam/blob/master/CS.PNG?raw=true)

## Description
Use `spam.py` to start spamming a server with fake beacons

## Usage
```
usage: spam.py [-h] [-u URL | -f FILE]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL
  -f FILE, --file FILE

```

## Note
You might want to use a tool like [TorghostNG](https://github.com/GitHackTools/TorghostNG) on your VM to hide your real IP or use [Whonix](https://www.whonix.org/)

# Prerequisites
Please install Tor before using this script and make sure it is running and listening on Port 9050

Afterwards install the following package:<BR>
<BR>
`pip install PySocks`<BR>
`pip install stem`<BR>
`pip install requests`<BR>
<BR>  
Please follow these steps to make sure this script is able to change the TOR IP programmatically<BR>
<BR>
`$ tor --hash-password MyStr0n9P#D`<BR>
`16:160103B8D7BA7CFA605C9E99E5BB515D9AE71D33B3D01CE0E7747AD0DC`<BR>
<BR>
Add this value to `/etc/torrc` (Path may vary depending on our distribution) for the value `HashedControlPassword` so it reads<BR>
`HashedControlPassword 16:160103B8D7BA7CFA605C9E99E5BB515D9AE71D33B3D01CE0E7747AD0DC`<BR>
<BR>
Afterwards uncomment the line<BR>
`ControlPort 9051`<BR>
Restart your tor service:
<BR>
`$ sudo service tor restart`
<BR>
Finally add your hash-password to spam_utils.py as "tor_password"

## Disclaimer
While this should be clear, this tool should be used only against infrastructure you own. Don't mess with systems you don't own! 


