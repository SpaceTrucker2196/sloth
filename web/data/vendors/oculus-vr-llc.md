---
name: "Oculus VR, LLC"
aliases: []
affiliates: []
country: US [1]
parent: Meta Platforms (acquired by Facebook in 2014; Facebook renamed Meta in 2021) [2]
founded: 2012 [2]
kind: brand [2]
device_classes: [console [2][3]]
found_in: ["Oculus Quest (2019) and Quest 2 (2020) standalone VR headsets [2][3]", "Oculus Rift CV1 PC headset (2016) and Oculus Touch controllers [2]", "Oculus Go (2017), built by Xiaomi [2]"]
radios: ["Wi-Fi 6 (Quest 2) [3]", "Bluetooth 5 (Quest 2) [3]"]
silicon: ["Qualcomm Snapdragon 821 in Oculus Go [2]", "Qualcomm Snapdragon 835 in Oculus Quest [2]", "Qualcomm Snapdragon XR2 in Quest 2 [2][3]", "Qualcomm Snapdragon XR2+ in Quest Pro and XR2 Gen 2 in Quest 3 [2]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Memory corruption in the Quest 2 VR Runtime SetPerformanceIdealFeatureState IPC handler, found by Meta in a 2021 review and never shipped to production [4]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Oculus VR was founded in 2012 by Palmer Luckey and others to develop a VR headset for video gaming; Facebook announced its US$2 billion acquisition in 2014, folded it into Facebook Reality Labs in 2020, announced its own rename to Meta in October 2021 and phased out the Oculus brand in 2022 [2]. The IEEE registry lists one MA-L block to "Oculus VR, LLC" at 1 Hacker Way, Menlo Park [1].

A MAC in this block is most likely an Oculus VR headset: the Rift CV1 shipped in 2016 with Touch controllers following, the Xiaomi-built Go in 2017, the Quest in 2019 and the Quest 2 in 2020 [2]. The Go ran a Snapdragon 821, the Quest a Snapdragon 835, the Quest 2 a Snapdragon XR2, the Quest Pro an XR2+ and the Quest 3 an XR2 Gen 2 [2]; Wikipedia gives the Quest 2 Wi-Fi 6 and Bluetooth 5 [3].

Meta's engineering blog describes a memory corruption bug in the Quest 2 VR Runtime service, reachable from any VR app over Runtime IPC, that was caught in a 2021 review and never reached production [4]. Randomization behaviour is not documented by the sources consulted, no teardown naming the Wi-Fi chip was reachable, and the FCC ID databases could not be consulted, so no grantee code is listed [2][3].

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Reality Labs (formerly Oculus VR) - Wikipedia - https://en.wikipedia.org/wiki/Oculus_VR (accessed 2026-10-27)
3. Meta Quest 2 - Wikipedia - https://en.wikipedia.org/wiki/Meta_Quest_2 (accessed 2026-10-27)
4. Meta Quest 2: Defense through offense - Engineering at Meta - https://engineering.fb.com/2023/09/12/security/meta-quest-2-defense-through-offense/ (accessed 2026-10-27)
