cardSignTransactionHash

// From pysatochip
```
echo -n "This is a test message to sign." | shasum -a 256
9024b67996b46a5698797aca7018ef309b1343d61ea08e4c1bab10b1fa2da29b


.venvZilla:pysatochip i830671$ python3 satochip_cli.py satochip-sign-hash --path "m/84'/0'/0'/0/0" --hash "9024b67996b46a5698797aca7018ef309b1343d61ea08e4c1bab10b1fa2da29b"
DEBUG: CardConnection.T0_protocol = 1
DEBUG: CardConnection.T1_protocol = 2
DEBUG: CardConnection.RAW_protocol = 65536
card_get_status
DEBUG: Trying T0 protocol...
DEBUG: Failed to connect using T0 protocol: Unable to connect with protocol: T0. Card protocol mismatch.: Card protocol mismatch. (0x8010000F)
DEBUG: Trying T1 protocol...
DEBUG: Successfully connected using T1 protocol
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: 00 a4 04 00 08 53 61 74 6f 43 68 69 70
NO ENCRYPTION: SELECT SATOCHIP
ENCRYPTED: APDU: 00 a4 04 00 08 53 61 74 6f 43 68 69 70
APDU: Response: , SW1: 90, SW2: 00
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 3c 00 00
NO ENCRYPTION: GET_STATUS
ENCRYPTED: APDU: b0 3c 00 00
APDU: Response: 00 0c 00 05 05 01 01 01 00 01 01 01, SW1: 90, SW2: 00
card_initiate_secure_channel
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 81 00 00 41 04 73 de 49 1c 8e 14 b6 0c 6c 5b 22 83 ca eb ba bd ae 0f c0 c9 fe 4d b3 a0 68 64 de 41 f5 8b bd 70 fd a5 a5 9e 92 23 89 1c 15 72 62 9a 5a 85 23 b3 f4 1c 6a 59 c0 68 56 7c 7a 96 86 f0 ce a6 da 4a
NO ENCRYPTION: INIT_SECURE_CHANNEL
ENCRYPTED: APDU: b0 81 00 00 41 04 73 de 49 1c 8e 14 b6 0c 6c 5b 22 83 ca eb ba bd ae 0f c0 c9 fe 4d b3 a0 68 64 de 41 f5 8b bd 70 fd a5 a5 9e 92 23 89 1c 15 72 62 9a 5a 85 23 b3 f4 1c 6a 59 c0 68 56 7c 7a 96 86 f0 ce a6 da 4a
APDU: Response: 00 20 19 87 fc 7c c3 44 5a b7 f1 99 08 bb df 65 cc 8c ae 25 20 f5 38 bc 5c ad 97 cf 6d b7 aa 80 cd dc 00 46 30 44 02 20 53 ac 06 c3 6a 07 ed bf 78 dd 48 40 73 a6 2e 36 6b 9c 82 99 dd d2 60 30 29 b5 59 fc 98 e4 96 8c 02 20 18 72 39 8c c9 87 89 5a 08 65 98 c7 e6 90 cf 5b 67 ed 4f 66 bb c2 26 86 ea dc 31 07 bf e3 0f 75 00 48 30 46 02 21 00 8e ff 58 81 84 be 15 0b ad 84 90 e4 92 04 50 58 60 62 47 8b 0e 33 40 0f f0 a2 12 4d 91 18 bf 87 02 21 00 bb 06 d2 62 ba 8a 2f eb 23 09 c3 44 78 24 e2 8b f6 0d 48 75 50 46 c3 be e0 ca 5c c3 4a 48 0b e7, SW1: 90, SW2: 00
INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 73 00 00
ENCRYPTION: BIP32_GET_AUTHENTIKEY
ENCRYPTED: APDU: b0 82 00 00 38 e0 b1 11 83 8b 3e f9 09 b0 40 f7 1b 00 00 00 03 00 10 12 08 4b 22 ee 26 cf 4b f0 93 e4 f3 86 54 60 e4 00 14 41 e4 17 26 7b 53 3c ba f0 b4 48 dd b3 cb 89 09 02 d2 99 c0
APDU: Response: 13 77 98 01 ad 3d b0 7c 9f 05 b6 9e 00 00 00 04 00 70 8c 5e 74 df ec 8f c5 5f d7 c0 1d f9 22 1b fd 5a 8f b6 e6 77 45 e6 3c 2a 0f c3 be ac 6d f5 43 ed 99 93 47 83 c9 fc 22 f2 d4 74 83 a8 5d 9d ca b7 53 2d a5 92 55 26 6c 44 69 9b 54 94 ea 8c 8e 86 97 e9 93 7e 45 d7 37 bb 04 d4 04 d7 33 8a c2 13 75 ab f1 0f 1b cd 34 0f 43 7e 55 e4 81 94 2e 5b 62 06 0a df a3 fc d9 4d e8 f1 e7 27 c6 03 c3 46, SW1: 90, SW2: 00
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 75 00 00 8d 00 20 c1 ea 37 d6 91 c0 3f 07 a8 3a 0d 71 b1 01 23 35 d0 36 df e0 39 64 bc 24 96 99 fb a7 26 26 f7 b7 00 47 30 45 02 21 00 cc 8f 47 82 7c b3 66 76 e8 14 5f 19 7a fd 78 22 41 f1 d2 2a 0a da f1 5d 58 a4 00 7a 2f b9 c8 37 02 20 29 2f c8 ea 9f 0d 93 98 31 a6 10 69 93 8e 64 ae 45 03 44 b5 1e 9a 84 bc 38 ae 40 9a b6 3c 21 db 00 20 9f 1a 76 f6 62 bf 55 d6 7f 10 2f 51 75 de 9b ca 75 3c ad 31 c9 d1 75 26 01 49 4c 48 70 b7 7b 32
ENCRYPTION: BIP32_SET_AUTHENTIKEY_PUBKEY
ENCRYPTED: APDU: b0 82 00 00 c8 9a 8b 82 6c 60 b4 71 0c c8 ab 4b 63 00 00 00 05 00 a0 80 1e d3 73 4a 33 ef b6 57 83 a5 dc 68 1a a5 42 3b 1e 45 16 e7 c1 74 ad c1 4a 22 14 ea 6b 25 38 f7 f5 2a 18 26 be 49 90 54 20 48 74 c0 ad f7 d7 c4 7e 9a 87 bd 61 0e 0e f0 33 af c8 24 59 b9 03 74 57 9a 24 fe 41 23 57 17 2d da 63 0e 32 c8 c2 65 f8 56 92 c3 34 1f 00 04 e7 6d f1 7a 05 ab 85 87 15 e5 7c eb b0 69 d6 19 b4 0b 4d d0 da 18 13 c6 e7 1e d5 89 57 07 48 cf 8c e1 b9 3e f3 6f b9 8c 13 1c af 3b 1c 69 de d3 f1 c0 f7 1c 6d 85 0d 6f 63 a5 b9 71 54 3b f0 a2 84 f8 b5 83 04 c4 75 00 14 7f 3a 44 7b bc 17 10 65 f6 2b 94 96 48 17 c8 30 1b 23 63 76
APDU: Response: 92 eb 47 7a 95 46 dd 06 c1 52 43 50 00 00 00 06 00 10 ee f0 b1 cd e9 d8 42 24 bf 54 66 a2 39 d0 85 1e, SW1: 90, SW2: 00
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 6d 05 40 14 80 00 00 54 80 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00
ENCRYPTION: GET_EXTENDED_KEY
ENCRYPTED: APDU: b0 82 00 00 48 eb 1b ff 22 bb 09 e5 08 0c dc 35 51 00 00 00 07 00 20 ea 15 f3 cc a4 f9 5b dd 5e dc e0 68 7b ec 81 86 df c6 3d f7 99 8d d7 63 42 14 70 dd 46 42 c2 99 00 14 8b e4 62 af bd b0 f0 ca 4e 46 63 1c dd 28 7d 6a a1 c9 42 47
APDU: Response: 8e 04 cd f4 4e 74 ea 40 c8 59 48 c7 00 00 00 08 00 e0 07 0e 3a dc 0c a0 46 bb 00 76 24 b5 c3 12 8d f0 62 2e 3e ef 4f eb a7 b1 d7 11 0b 89 ec 7c ad 27 66 84 ec 83 77 d7 14 67 e8 bd 5f 62 96 e0 63 dd b3 fd 76 b1 d1 e7 f9 78 38 35 b0 2f b2 a9 f1 4c 7a 90 9a 78 2f 73 0d 43 7d 53 a7 79 71 75 cc 88 90 8e e0 c5 f0 2d 19 58 9e 0d c5 4f b6 dd 04 3e ae 70 8b 05 e5 dd 30 9a 85 7a 25 0b b7 c3 51 fc 2a 77 92 70 4b ae d3 84 c3 4e e7 01 d0 77 69 30 84 dc a4 6b cc 37 3f 46 4a 61 b2 cf 28 6d 3b bb 11 7f 8c dd 44 e0 e1 80 52 6d ff 84 a8 ea 64 94 2b be 61 40 37 90 75 ff ca 52 32 37 29 91 8e 2a 92 c3 03 48 f3 54 d1 8c 30 d3 74 43 ed e6 a6 d9 35 04 3e f1 95 7a 7e d0 87 61 e3 3f 2b 3d 9f f7 5e 4a e5 f8 e5 fe ca 48 21 86 cf 88 e8 1b eb 0e, SW1: 90, SW2: 00
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 7a ff 00 36 90 24 b6 79 96 b4 6a 56 98 79 7a ca 70 18 ef 30 9b 13 43 d6 1e a0 8e 4c 1b ab 10 b1 fa 2d a2 9b 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
ENCRYPTION: SIGN_TRANSACTION_HASH
ENCRYPTED: APDU: b0 82 00 00 68 a0 74 7c 2f f1 14 f0 ea cc 19 36 e0 00 00 00 09 00 40 23 46 c0 42 44 03 47 9b e8 e6 a6 92 52 b1 94 7b 10 99 8b bb a4 4f 5e 08 e9 f0 d9 35 17 8b 22 22 4c 49 23 55 be 88 7c f8 26 e2 6e 43 45 d7 ab ec 36 0d ed 50 e6 07 c9 b4 75 6f 59 51 57 fe 83 18 00 14 42 25 c6 cd 3b 82 93 89 6d 2c 0e ea 83 f9 a5 cb 86 a5 9f ee
APDU: Response: 6c 1b ae 91 56 0a ea 21 ef 11 12 3d 00 00 00 0a 00 50 d8 5e 48 cb 15 47 a8 37 55 8f fc 80 ae 57 3f e9 ea 72 c9 d5 f2 ef 75 52 a1 3c 77 dc f5 ac 0a 5f 42 97 fc 51 f4 33 4e da e5 96 68 06 eb 4f e0 4f 76 d3 f7 da c8 d7 38 1b fc 3c fc 23 87 c7 b5 8e ee 94 51 23 34 31 ac 7a 3f b6 e6 22 a5 2b b8 f8, SW1: 90, SW2: 00
Signature (hex): 3046022100a52c9ce5624b809864fbe3948748aac65232f1309e201f18ed6f967f3b75fa9b022100a03d54c38ee67b5c952ae5f54562ac802a0fbef9c288a314bd0967a1404988f9
.venvZilla:pysatochip i830671$ 

.venvZilla:pysatochip i830671$ python3 satochip_cli.py satochip-sign-message --path "m/84'/0'/0'/0/0" --message "This is a test message to sign."
DEBUG: CardConnection.T0_protocol = 1
DEBUG: CardConnection.T1_protocol = 2
DEBUG: CardConnection.RAW_protocol = 65536
card_get_status
DEBUG: Trying T0 protocol...
DEBUG: Failed to connect using T0 protocol: Unable to connect with protocol: T0. Card protocol mismatch.: Card protocol mismatch. (0x8010000F)
DEBUG: Trying T1 protocol...
DEBUG: Successfully connected using T1 protocol
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: 00 a4 04 00 08 53 61 74 6f 43 68 69 70
NO ENCRYPTION: SELECT SATOCHIP
ENCRYPTED: APDU: 00 a4 04 00 08 53 61 74 6f 43 68 69 70
APDU: Response: , SW1: 90, SW2: 00
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 3c 00 00
NO ENCRYPTION: GET_STATUS
ENCRYPTED: APDU: b0 3c 00 00
APDU: Response: 00 0c 00 05 05 01 01 01 00 01 01 01, SW1: 90, SW2: 00
card_initiate_secure_channel
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 81 00 00 41 04 3a c7 69 83 30 25 71 0b 35 99 b2 d8 f9 25 be eb 63 99 29 9d 78 8a 2d 13 1a 9e b1 09 6f da bf ca ac b4 c6 45 80 6e a3 3f 08 c4 74 a4 10 32 a9 cd e4 ff 44 09 38 b6 0f 26 e8 18 03 d5 48 c6 d2 2d
NO ENCRYPTION: INIT_SECURE_CHANNEL
ENCRYPTED: APDU: b0 81 00 00 41 04 3a c7 69 83 30 25 71 0b 35 99 b2 d8 f9 25 be eb 63 99 29 9d 78 8a 2d 13 1a 9e b1 09 6f da bf ca ac b4 c6 45 80 6e a3 3f 08 c4 74 a4 10 32 a9 cd e4 ff 44 09 38 b6 0f 26 e8 18 03 d5 48 c6 d2 2d
APDU: Response: 00 20 58 03 94 95 26 4e d0 2e 6e 53 88 2f b9 89 26 ea 7d 97 c3 c5 7e b6 5f f8 23 42 cc 58 e4 02 59 29 00 47 30 45 02 21 00 e4 ee 23 bf 3f 0d f2 61 f8 9c 5b 41 5c b8 ac a3 e6 39 47 01 53 e4 e2 a5 fc 76 c7 7d d4 c5 c1 2a 02 20 77 58 eb 92 0d e4 b0 70 48 73 08 9a 94 05 37 e2 0d 97 0b 67 29 a4 92 e9 f4 98 96 f7 7d f4 e1 fb 00 47 30 45 02 21 00 b3 f2 f2 d6 63 76 0d 75 70 aa 1c ed 34 c3 a5 48 e0 53 bd 2a ab 38 0a 22 dd 1f a2 d5 93 f0 76 a0 02 20 32 a4 d8 53 f8 f1 11 b3 23 96 32 15 9e cc 2c 04 d6 8d 32 1c b5 eb e6 8b 36 d9 f7 22 15 de 44 f6, SW1: 90, SW2: 00
DEBUG: message_byte: b'This is a test message to sign.'
INFO: PIN value recovered from environment variable 'PYSATOCHIP_PIN'
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 73 00 00
ENCRYPTION: BIP32_GET_AUTHENTIKEY
ENCRYPTED: APDU: b0 82 00 00 38 08 e7 15 f4 c1 70 a3 b0 1f bf d6 d3 00 00 00 03 00 10 0a 0b 44 38 c8 39 73 15 cf cf 11 e5 dc 1e 51 cd 00 14 0f 83 2b 2d cb 11 3c f3 46 9b 52 27 86 2f 35 c5 29 fa dc 98
APDU: Response: 05 d3 29 db 4b 47 c3 65 af df 9c f4 00 00 00 04 00 70 61 56 c9 88 cc 8f 74 7e 4f 3d 62 56 26 ef 1a 39 11 1a 69 b7 22 d0 47 70 7b 5e 59 39 4f 34 6d 14 ba 7d 9e de cc c6 3f 37 a6 92 50 36 ef f8 a7 6c e6 37 0e 3e 41 6f 2d 7f 59 cc 2b 8c 2d c7 49 9e 58 ee b8 00 ae ae 0d cb 87 c0 97 e7 ba 4d 99 11 be c9 43 1a 9d 4d 59 01 1b 67 b4 0d f4 08 d6 d0 8e 21 2f 28 bf d1 64 93 47 98 24 27 6c 41 91 96, SW1: 90, SW2: 00
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 75 00 00 8d 00 20 c1 ea 37 d6 91 c0 3f 07 a8 3a 0d 71 b1 01 23 35 d0 36 df e0 39 64 bc 24 96 99 fb a7 26 26 f7 b7 00 47 30 45 02 20 71 f4 f4 ec aa 18 2e 31 df 51 60 c2 27 11 c5 b6 0d ea 90 2f 5f fc 2f f8 0e bf 9e 70 8f 8e ef 50 02 21 00 f4 66 28 86 64 39 6e 8c 68 ba 4b 6d e4 c4 9d b4 9e 88 42 53 f4 d7 03 ac b7 3a e7 78 ee c9 67 f8 00 20 9f 1a 76 f6 62 bf 55 d6 7f 10 2f 51 75 de 9b ca 75 3c ad 31 c9 d1 75 26 01 49 4c 48 70 b7 7b 32
ENCRYPTION: BIP32_SET_AUTHENTIKEY_PUBKEY
ENCRYPTED: APDU: b0 82 00 00 c8 3b 22 5c ae 37 21 87 88 b3 a5 27 4a 00 00 00 05 00 a0 bf f0 bd 8c 10 de 34 6b d7 37 ce 4f 5d bc 2d 3b ec ad 6a f9 33 fc 62 ed f9 67 cd f3 5c dd 2d 0c d4 84 06 47 82 ea 04 08 2a fe b6 df c6 f8 3a 3b 69 8f 07 a1 ff ca 3c f4 6e d2 76 ef 8d ff c6 bd 4e 3d 28 38 c8 1a 1f 5b 37 ae b3 ce de dc 85 df 9f bc b8 eb 78 7b 8f e8 57 c5 bf fb bb 89 a5 db d4 bf 66 f6 37 2b 66 8e 05 9b 88 dc 15 84 b7 63 c4 97 60 64 97 8c 76 6d 59 58 11 a8 5e 3c b2 90 f3 ba f7 62 5a 43 4a 8e 93 1a e2 43 4f 60 df 70 5f 50 2d 6b 07 54 4f f4 2e be cb 65 0c 70 4b 04 00 14 09 1c ff 9b 75 70 b7 af b5 8d 97 0b 6b 42 12 cf 8f ba 1c 55
APDU: Response: 7e 04 23 5e f7 03 f4 0c af 30 25 63 00 00 00 06 00 10 f2 90 60 87 8c b3 82 51 38 07 6d 0f 46 2b be 59, SW1: 90, SW2: 00
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 6d 05 40 14 80 00 00 54 80 00 00 00 80 00 00 00 00 00 00 00 00 00 00 00
ENCRYPTION: GET_EXTENDED_KEY
ENCRYPTED: APDU: b0 82 00 00 48 a9 a8 9e a7 ae a9 3a 0e 15 cf ef 6b 00 00 00 07 00 20 eb a3 c1 71 aa 2b d8 70 72 2d bc 09 77 ff 2b d4 b9 80 7c 4f 70 ad b2 6b 09 cc c2 4c 01 bd 15 46 00 14 a5 15 5a d8 4a cf 46 6b f7 2c 61 b5 4e 8e a6 34 7f 3f 98 1b
APDU: Response: 23 71 12 3c bd b3 f9 24 a5 5d 3e 9b 00 00 00 08 00 e0 53 56 8c a3 4f 03 c7 07 67 c7 ed 87 82 77 4e 81 0d 7e 15 33 53 e0 a5 98 e6 7b d9 ca 0f 6a ac 4b 7c ce 25 ed 0c e7 29 a2 67 42 79 f9 52 67 a7 2e f1 fe 1a 3f 79 3b 1e 93 79 62 bd 23 b0 3e 33 27 de fe c1 79 ec 26 33 8f 57 0d c8 d1 36 f0 67 35 08 97 e3 a0 7b 1d dc d2 e7 be 2a 15 8f f5 96 68 a8 ef d6 d0 78 b2 68 30 45 2c a5 4c 7e e6 e9 90 0d 24 7d 12 04 bf 11 0f bb 56 1a e3 b9 4d 1e c7 24 22 3a a5 5c 88 59 62 01 ec f5 dd 09 0f 19 d1 4e 7e f4 71 a8 23 90 ec 7d f0 6f 7f e6 3a d4 0f 4f ee 02 18 3e 23 37 33 1b b7 ec 05 22 06 9a 23 df 4e cc e6 a2 72 00 f5 a0 89 6b 81 74 f2 c2 84 b0 fe 70 f2 f2 20 01 eb 0d 4b ad 26 34 c0 ba ba 84 bb e9 02 4e b9 e7 b8 a9 8f db 3d dc ac 59 d2, SW1: 90, SW2: 00
PreSign: keyslot: 255, pubkey: <pysatochip.ecc.ECPubkey object at 0x102e51150>, message_byte: b'This is a test message to sign.', hmac: b''
In card_sign_message
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
```
APDU: plain_apdu: b0 6e ff 01 04 00 00 00 1f
ENCRYPTION: SIGN_MESSAGE
ENCRYPTED: APDU: b0 82 00 00 38 4a b4 3c ac 1a 55 d5 d5 42 cf 05 6c 00 00 00 09 00 10 a1 f9 4d 3c d2 12 63 aa f8 97 6e 31 0c 05 c9 75 00 14 ed fd a4 75 8a fc 83 4c dc 98 20 d2 6a e5 f8 b0 d4 a2 3c c6
APDU: Response: , SW1: 90, SW2: 00
```
ATTEMPT: select_apdu: 00 a4 04 00 0a a0 00 00 00 62 03 01 0c 06 01
APDU: plain_apdu: b0 6e ff 03 21 00 1f 54 68 69 73 20 69 73 20 61 20 74 65 73 74 20 6d 65 73 73 61 67 65 20 74 6f 20 73 69 67 6e 2e
ENCRYPTION: SIGN_MESSAGE
ENCRYPTED: APDU: b0 82 00 00 58 9b 6d 57 f4 4b 7a 54 70 f9 81 ab eb 00 00 00 0b 00 30 ad 3f 23 76 61 30 6f 14 94 9f f7 2c a2 91 f4 8d e5 57 fc fc 71 7f 56 4c b8 86 da 39 c3 a3 1f 44 b7 cb 48 97 b8 48 cd 35 3d 5c 35 d5 fd ee 3e c7 00 14 bb 67 2c e9 cf 48 13 c0 ed 9a c5 7d f6 aa 11 19 80 a8 db d5
APDU: Response: 08 b7 53 06 6d c0 27 ce 5b b7 93 c4 00 00 00 0c 00 50 f5 9e c0 78 21 1a 4e 84 0b 9b f3 06 9f 1e 72 be d2 49 24 cc 71 d8 df 90 05 83 e1 6f 1d 38 ca 69 01 3a 82 aa 2e d1 4a f7 c0 a2 b7 6c 1b f7 f5 f8 4e ca f4 72 62 df ae c0 f4 df 63 c4 2d 44 55 15 f1 f2 1f 02 01 40 62 96 51 16 15 6c 41 a8 19 e0, SW1: 90, SW2: 00
DEBUG: hash: b'\xb3\x97I\xfdC@\xea\x7f\x817\x04\xd2@\xb4\xca6.\x07)\x0846d\xebk\xcaO\nQ\x8d\xe4\xba'
Signature (Base64): H8Bspb9iOjR8poEthBRuv6c9d1DtuOdLwAIzCKavIW0nMQpkTvjfNAN9r0hB6VeGPysJP60YaMdcC92bMsIPl7M=
.venvZilla:pysatochip i830671$ 
```