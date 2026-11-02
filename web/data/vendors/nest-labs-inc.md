---
name: Nest Labs Inc.
aliases: []
country: US [1][2]
parent: Google (acquired 2014) [2]
founded: 2010 [2]
kind: brand [2]
device_classes: [smart-home [2], camera [2]]
found_in: ["Nest Learning Thermostat [2][3]", "Nest Protect smoke and CO alarm [2]", "Nest Cam, Nest Cam IQ and Nest Hello [2]", "Nest Secure (Nest Guard, Nest Detect, Nest Tag) [2]"]
radios: ["Wi-Fi 4 [3]", "2.4 GHz [3]", "Bluetooth, version not documented [2]", "Thread/Zigbee (802.15.4) [3]"]
silicon: ["TI WL1270B 802.11b/g/n, Ember EM357 ZigBee/802.15.4 SoC and TI AM3703 Sitara Cortex-A8 in the Nest Learning Thermostat 2nd generation [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Nest Cam flaws reported March 2017, one letting a burglar stop recording over the always-on Bluetooth; fixed later that month [2]", "Weave protocol flaws in Nest Cam IQ Indoor: CVE-2019-5035 PASE pairing-code brute force and CVE-2019-5037 certificate-loading denial of service [4][5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Nest Labs was founded in 2010 by former Apple engineers Tony Fadell
and Matt Rogers; Google announced its purchase for 3.2 billion US
dollars in cash in January 2014, merged it into its hardware division
in 2018, where it kept a separate Palo Alto headquarters, and since
2019 Google Nest has been the brand for all of Google's home products
[2]. The IEEE registry lists two MA-L blocks to Nest Labs Inc. at 3400
Hillview Ave., Palo Alto [1]. A MAC in these blocks is most likely an
early-generation Nest home device: the Wi-Fi Learning Thermostat, the
Protect smoke and CO alarm, the Nest Cam line or the Nest Secure alarm
system [2].

iFixit's teardown of the second-generation Learning Thermostat found a
TI WL1270B 802.11b/g/n Wi-Fi part, an Ember EM357 ZigBee/802.15.4 SoC
with a Skyworks 2.4 GHz 802.15.4 front end, and a TI AM3703 Sitara
Cortex-A8 processor, with both radios on 2.4 GHz [3], so expect both
Wi-Fi and an 802.15.4 radio from these devices.

Security flaws in Nest Cam products reported in March 2017 included
one letting a burglar use the camera's always-on Bluetooth to stop it
recording, and Nest shipped a fix later that month [2]. NVD records
Weave protocol bugs in the Nest Cam IQ Indoor, among them
CVE-2019-5035, where crafted Weave packets brute force the PASE pairing
code, and CVE-2019-5037, a denial of service in certificate loading
[4][5]. Randomization is not documented by the sources consulted, and
FCC grantee codes are not listed because the FCC ID databases refused
the session that verified this entry.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Google Nest - Wikipedia - https://en.wikipedia.org/wiki/Google_Nest (accessed 2026-10-27)
3. Nest Learning Thermostat 2nd Generation Teardown - iFixit - https://es.ifixit.com/Desmontaje/Nest+Learning+Thermostat+2nd+Generation+Teardown/13818 (accessed 2026-10-27)
4. CVE-2019-5035 - NVD API record - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-5035 (accessed 2026-10-27)
5. CVE-2019-5037 - NVD API record - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-5037 (accessed 2026-10-27)
