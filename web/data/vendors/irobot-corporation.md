---
name: "iRobot Corporation "
aliases: ["iRobot Corporation"]
affiliates: []
country: US [1][2]
parent: Shenzhen Picea Robotics, named as acquirer under the restructuring that accompanied the December 2025 Chapter 11 filing [2]
founded: 1990 [2]
kind: brand [2]
device_classes: [smart-home [2][3]]
found_in: ["Roomba robot vacuums, Wi-Fi models from the Roomba 670/690 onward [2][3]"]
radios: ["2.4 GHz (every Wi-Fi Roomba) [3]", "5 GHz (Roomba i6/i7/i8, s9, j7/j9, Combo j5, Combo j7+/j9+, Combo 10 Max) [3]", "Bluetooth, used for setup where possible (version not documented) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["2020 leak of development-unit Roomba J7 camera images: of about 2 million images shared with labelling contractor Scale AI, workers posted at least 15 to private social-media groups [2]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

iRobot is the Bedford, Massachusetts maker of the Roomba robot vacuum and the Braava floor-mopping robot, founded in 1990 by Rodney Brooks, Colin Angle and Helen Greiner of MIT's Artificial Intelligence Lab [2]. The IEEE registry lists three MA-L blocks at 8 Crosby Drive, Bedford, one of them under the spelling with a trailing space that this file is named for [1]. Amazon's announced 1.7 billion dollar takeover collapsed in January 2024, and on 14 December 2025 the company filed for Chapter 11 under an agreement by which Shenzhen Picea Robotics and Santrum Hong Kong would take it private [2].

A MAC in these blocks is most likely a Wi-Fi connected Roomba on a home network [2][3]. iRobot's own compatibility table says every Wi-Fi Roomba from the 670/690 onward joins 2.4 GHz, that the i6/i7/i8, s9, j7/j9, Combo j5, Combo j7+/j9+ and Combo 10 Max also join 5 GHz, that models below the 670 have no Wi-Fi at all, and that iRobot uses Bluetooth to set up the robot where possible [3]. iRobot's current site lists Roomba vacuums, Roomba combo vacuum-mops and Braava robot mops [4]; no source consulted documents a Braava's radios, so Braava is not listed under found_in.

In 2020 images taken by development versions of the Roomba J7 were posted to social media after iRobot shared about 2 million images with Scale AI for labelling; iRobot ended that relationship [2]. An NVD keyword search for iRobot returned one CVE, for an unrelated WordPress plugin, and none naming iRobot hardware [5].

The FCC ID databases (fccid.io, fcc.report, apps.fcc.gov) refused automated access from this session and no teardown naming the Wi-Fi chip was reachable, so silicon and FCC grantee codes are not listed and randomization is unknown.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. iRobot - Wikipedia - https://en.wikipedia.org/wiki/IRobot (accessed 2026-10-27)
3. Which Wi-Fi networks can my robot connect to - iRobot support - https://homesupport.irobot.com/articles/en_US/Knowledge/17734 (accessed 2026-10-27)
4. iRobot home page - https://www.irobot.com/ (accessed 2026-10-27)
5. NVD CVE API keyword search irobot - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=irobot (accessed 2026-10-27)
