---
name: Sleep Number
aliases: []
affiliates: []
country: US [1][2]
parent: Sleep Country Canada, whose subsidiary SNBR Inc. bought substantially all of the company's assets (completed 31 July 2026) [2]
founded: 1987 [2]
kind: brand [2]
device_classes: [smart-home [3][4]]
found_in: ["Sleep Number smart beds, whose hub talks to Sleep Number cloud endpoints [3][4]"]
radios: ["Wi-Fi (generation not documented) [4]", "Bluetooth (version not documented) [4]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["Smart bed hub found in 2024 to carry a hidden SSH access path that let Sleep Number connect to it, reported by a researcher who gained root through the hub's UART console [4][5]"]
confidence: {country: documented, silicon: unknown, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Sleep Number is the Minneapolis maker of adjustable air mattresses, founded in 1987 by Robert and JoAnne Walker as Select Comfort, renamed Sleep Number Corporation in November 2017 and listed on Nasdaq as SNBR; in 2026 a bankruptcy court approved the sale of substantially all of its assets to SNBR Inc., a wholly owned subsidiary of Sleep Country Canada, completed on 31 July 2026 [2]. The IEEE registry lists two MA-L blocks and one MA-M block to "Sleep Number" at 1001 Third Avenue South, Minneapolis [1]. A MAC in these blocks is most likely the networked hub of a Sleep Number smart bed: the Home Assistant SleepIQ integration is cloud polling, and the bed talks to endpoints on sleepnumber.com and to an AWS Firehose data collection service [3].

In 2024 a researcher building a Homebridge plugin for the bed reached the hub's console over UART, gained root by editing boot environment variables, found it running a 2018 Linux build, and found a hidden path in its file system that let Sleep Number connect to the hub over SSH; he advised turning off the hub's Wi-Fi and using only Bluetooth, which shows the hub carries both radios [4]. Hackaday reported the same root access and phone-home, backdoor-like connection on 30 June 2024, and that Sleep Number asked for the cloud plugin to be shut down [5].

The company's support pages and the FCC ID databases refused automated access from this session, so Wi-Fi band and Bluetooth version, silicon and FCC grantee codes are not listed, and randomization is unknown. The registry also lists blocks under the former name "Select Comfort"; they are not listed as aliases here because that is a different registry name, not a spelling of this one.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) and MA-M assignments (mam.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Sleep Number - Wikipedia - https://en.wikipedia.org/wiki/Sleep_Number (accessed 2026-10-27)
3. SleepIQ integration - Home Assistant - https://www.home-assistant.io/integrations/sleepiq/ (accessed 2026-10-27)
4. Engineer finds backdoor in Sleep Number smart beds - SecurityLab.ru - https://www.securitylab.ru/news/549731.php (accessed 2026-10-27)
5. Smart bed tag (Root Your Sleep Number Smart Bed, Discover It Phoning Home) - Hackaday - https://hackaday.com/tag/smart-bed (accessed 2026-10-27)
