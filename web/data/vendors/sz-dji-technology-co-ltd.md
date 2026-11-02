---
name: "SZ DJI TECHNOLOGY CO.,LTD"
aliases: []
country: CN [1]
parent: "independent (private; DJI states state-affiliated investors hold under 6% with under 1% of votes) [1]"
founded: 2006 [1]
kind: brand
device_classes: [drone, camera, industrial]
found_in: ["Consumer drones: Mavic, Mini, Air, Phantom, Spark, Neo, Flip, Inspire [1]", "Industrial/agricultural drones: Matrice, Agras, FlyCart, Dock [1]", "Mavic 3 Pro, Mavic 3, Mavic 3 Classic, Mavic 3 Enterprise, Matrice 300, Matrice M30 and Mini 3 Pro (named in CVE-2023-51454/51455/51456) [9]", "Osmo handheld gimbal cameras and Ronin cinema gimbals [1]", "RoboMaster educational robots [1]"]
radios: ["Wi-Fi: 'Enhanced Wi-Fi' link on the original Mavic Mini, 5.8 GHz only on MT1SS5 and 2.4 or 5.8 GHz on MT1SD25 [5]", "2.4 GHz (Mavic Mini MT1SD25) [5]", "5 GHz (5.8 GHz band, Mavic Mini) [5]", "BLE: DUML protocol messages carried over Bluetooth Low Energy [8][10]", "Proprietary OcuSync 1.0 / 2.0, O3, O3+, O4, O4+ video link replacing Wi-Fi from the Mini 2 on (bands not stated) [4][5]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["Added October 2022 to the US DoD Section 1260H 'Chinese military companies' list; the US District Court for D.C. ruled against DJI's challenge in September 2025 and DJI appealed [6]", "December 2025: US FCC banned import, marketing and sale of new DJI models; models already approved were excluded [1]", "CVE-2022-29945: DJI drones of 2017-2022 broadcast the operator's location unencrypted via AeroScope [9]", "CVE-2023-51454/51455/51456: memory corruption in v2_sdk_service on TCP port 10000 on Mavic 3 family, Matrice 300/M30 and Mini 3 Pro [9]", "CVE-2026-77812: DUML messages over BLE are unencrypted, exposing the drone's Wi-Fi SSID and PSK to a passive listener [8][10]", "CVE-2026-78306: unauthenticated DUML command interface over Bluetooth permits changing the drone's Wi-Fi configuration [8]", "CVE-2026-78251: FTP service with hard-coded credentials shared across models; CVE-2026-78255: unauthenticated HTTP media server; CVE-2026-78321: media-server connection exhaustion DoS [8]", "DJI runs its own Security Response Center for vulnerability submissions (security.dji.com) [11]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
SZ DJI Technology Co., Ltd. is the Shenzhen drone maker founded in 2006 by Frank Wang; it is privately held and describes state-affiliated investors as holding under 6% of equity and under 1% of votes [1]. The IEEE lists ten MA-L blocks for the registrant [7], and its products are consumer and industrial drones, Osmo and Ronin gimbals and RoboMaster robots [1], so a hit is most likely a DJI aircraft, controller or camera. The original Mavic Mini used an 'Enhanced Wi-Fi' link on 5.8 GHz (and 2.4 GHz on the MT1SD25 variant), while from the Mini 2 on, and on the Mavic line, the video link is DJI's proprietary OcuSync / O3 / O4 family rather than standard Wi-Fi [4][5]; current aircraft also run the DUML control protocol over Bluetooth Low Energy [8][10]. The chips inside are not named in any source reached in this session, so silicon is recorded as not documented; the FCC grantee pages on fccid.io refused the fetch (HTTP 403), so no grantee code is recorded, and no statement on MAC randomization was found. Security context matters for this vendor: DJI has been on the US DoD 1260H list since October 2022 and lost its court challenge in September 2025 [6], the FCC banned new DJI models from import and sale in December 2025 [1], and published CVEs cover unencrypted AeroScope operator-location broadcasts (CVE-2022-29945) and memory corruption in the SDK service on port 10000 [9], plus a 2026 batch showing Wi-Fi credentials leaking over BLE, an unauthenticated Bluetooth DUML interface that can change the drone's Wi-Fi configuration, hard-coded FTP credentials and an unauthenticated media server [8][10]. The company operates a security response center for disclosures [11].
## Sources
1. DJI - Wikipedia - https://en.wikipedia.org/wiki/DJI (accessed 2026-10-27)
2. SZ DJI TECHNOLOGY CO., LTD FCC ID Applications (SS3) - fccid.io - https://fccid.io/SS3 (accessed 2026-10-27) (not reachable 2026-10-27)
3. FCC ID SS3-MT5MFND25 - DJI Mini 5 Pro - fccid.io - https://fccid.io/SS3-MT5MFND25 (accessed 2026-10-27) (not reachable 2026-10-27)
4. DJI Mavic - Wikipedia - https://en.wikipedia.org/wiki/DJI_Mavic (accessed 2026-10-27)
5. DJI Mini - Wikipedia - https://en.wikipedia.org/wiki/DJI_Mini (accessed 2026-10-27)
6. 1260H list - Wikipedia - https://en.wikipedia.org/wiki/1260H_list (accessed 2026-10-27)
7. SZ DJI TECHNOLOGY CO.,LTD MAC address blocks - maclookup.app - https://maclookup.app/vendors/sz-dji-technology-co-ltd (accessed 2026-10-27)
8. CVE search dji / mini 5 pro - CIRCL vulnerability-lookup API - https://cve.circl.lu/api/search/dji/mini%205%20pro (accessed 2026-10-27)
9. CVE search dji / mavic_3_firmware - CIRCL vulnerability-lookup API - https://cve.circl.lu/api/search/dji/mavic_3_firmware (accessed 2026-10-27)
10. CVE search dji / dji mini 4 pro - CIRCL vulnerability-lookup API - https://cve.circl.lu/api/search/dji/dji%20mini%204%20pro (accessed 2026-10-27)
11. DJI Security Response Center - https://security.dji.com/ (accessed 2026-10-27)
