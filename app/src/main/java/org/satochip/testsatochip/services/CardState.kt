package org.satochip.testsatochip.services

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.lifecycle.MutableLiveData
import org.bitcoinj.crypto.MnemonicCode
import org.satochip.android.NFCCardManager
import org.satochip.client.ApplicationStatus
import org.satochip.client.Constants
import org.satochip.client.SatochipCommandSet
import org.satochip.client.SatochipParser
import org.satochip.client.seedkeeper.SeedkeeperExportRights
import org.satochip.client.seedkeeper.SeedkeeperLog
import org.satochip.client.seedkeeper.SeedkeeperMasterSeedResult
import org.satochip.client.seedkeeper.SeedkeeperSecretHeader
import org.satochip.client.seedkeeper.SeedkeeperSecretObject
import org.satochip.client.seedkeeper.SeedkeeperSecretOrigin
import org.satochip.client.seedkeeper.SeedkeeperSecretType
import org.satochip.client.seedkeeper.StatusWord
import org.satochip.io.APDUResponse
import org.satochip.testsatochip.data.AuthenticityStatus
import org.satochip.testsatochip.data.NfcResultCode
import org.satochip.testsatochip.data.TestItems
import java.time.Instant
import java.security.MessageDigest

private const val TAG = "CardState"

@SuppressLint("StaticFieldLeak")
object CardState {

    lateinit var context: Context // initialized in TestSatochipViewModel
    var activity: Activity? = null

    lateinit var cmdSet: SatochipCommandSet
    private var parser: SatochipParser? = null
    private var isCardDataAvailable: Boolean = false
    var authentikeyHex: String = ""

    //NFC
    var resultCodeLive =
        MutableLiveData<NfcResultCode>(NfcResultCode.Busy) //NfcResultCode = NfcResultCode.Ok

    var authenticityStatus = MutableLiveData<AuthenticityStatus>(AuthenticityStatus.Unknown)
    var certificateList = MutableLiveData<MutableList<String>>() // todo: not livedata?


    //test
    var nbTestTotal = 0
    var nbTestSuccess = 0

    private lateinit var cardStatus: ApplicationStatus

    // to define action to perform
    var actionType: TestItems = TestItems.DoNothing
    var actionIndex: Int = 0

    var isConnected =
        MutableLiveData(false) // the app is connected to a card // updated in SatochipCardListener


    fun initialize(cmdSet: SatochipCommandSet) {
        SatoLog.d(TAG, "initialize START")
        
        // Configure logging to capture satochip library info messages
        System.setProperty("java.util.logging.ConsoleHandler.level", "INFO")
        System.setProperty("java.util.logging.Level", "INFO")
        
        // Additional logging configuration for satochip library
        System.setProperty("org.satochip.client.level", "DEBUG")
        System.setProperty("org.satochip.client.SATOCHIPLIB.level", "DEBUG")
        
        // Enable Android logging for the satochip package
        android.util.Log.d(TAG, "Logging configured for satochip library")
        SatoLog.d(TAG, "Logging configured for INFO level")
        
        CardState.cmdSet = cmdSet
        parser = cmdSet.parser
        SatoLog.d(TAG, "initialize action: $actionType")
        SatoLog.d(TAG, "initialize index: $actionIndex")
        resultCodeLive.postValue(NfcResultCode.Busy)

        onConnection()
    }

    fun scanCardForAction(activity: Activity) {
        SatoLog.d(TAG, "scanCardForAction thread START")
        this.activity = activity
        val cardManager = NFCCardManager()
        cardManager.setCardListener(SatochipCardListenerForAction)
        cardManager.start()

        resultCodeLive.postValue(NfcResultCode.Busy)

        val nfcAdapter = NfcAdapter.getDefaultAdapter(activity) //context)
        nfcAdapter?.enableReaderMode(
            activity,
            cardManager,
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            null
        )
        SatoLog.d(TAG, "scanCardForAction thread END")
    }

    fun disableScanForAction() {
        SatoLog.d(TAG, "disableScanForAction Start")
        if (activity != null) {
            if (activity?.isFinishing() == true) {
                SatoLog.e(TAG, "NFCCardService disableScanForAction activity isFinishing()")
                return;
            }
            val nfcAdapter = NfcAdapter.getDefaultAdapter(activity)
            nfcAdapter?.disableReaderMode(activity)
            SatoLog.d(TAG, "disableScanForAction disableReaderMode!")
        }
    }

    fun <T> checkEqual(lhs: T, rhs: T, tag: String) where T : Any, T : Comparable<T> {
        if (lhs != rhs) {
            val msg = "CheckEqual failed: got $lhs but expected $rhs in $tag"
            SatoLog.e("testSatochip", "$msg, $tag")
            throw Exception("test error: [$tag] $msg")
        } else {
            SatoLog.d("testSatochip", "CheckEqual ok for: $lhs")
        }
    }

    fun checkByteArrayEqual(lhs: ByteArray, rhs: ByteArray, tag: String) {
        if (!lhs.contentEquals(rhs)) {
            val msg =
                "CheckEqual failed: got ${lhs.toHexString()} but expected ${rhs.toHexString()} in $tag"
            SatoLog.e("testSatochip", "$msg, $tag")
            throw Exception("test error: [$tag] $msg")
        } else {
            SatoLog.d("testSatochip", "CheckEqual ok for: ${lhs.toHexString()}")
        }
    }

    // Extension function to convert ByteArray to hexadecimal string representation
    fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }

    fun randomString(count: Int): String {
        val letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>&!%=+/.:$@€#"
        return (1..count)
            .map { letters.random() }
            .joinToString("")
    }

    fun randomBytes(count: Int): ByteArray {
        val bytes = ByteArray(count)
        val secureRandom = java.security.SecureRandom()

        try {
            secureRandom.nextBytes(bytes)
            return bytes
        } catch (e: Exception) {
            throw Exception("error $e")
        }
    }

    fun generateMnemonic(strength: Int): String {
        val entropy = ByteArray(strength / 8)
        java.security.SecureRandom().nextBytes(entropy)
        return MnemonicCode.INSTANCE.toMnemonic(entropy).joinToString(" ")
    }

    fun stringToList(inputString: String?): List<String?>? {
        return inputString?.split("\\s+".toRegex())
    }

    fun getCardVersionInt(cardStatus: ApplicationStatus): Int {
        return cardStatus.getCardVersionInt()
    }

    //Card connection
    @RequiresApi(Build.VERSION_CODES.O)
    fun onConnection() {
        SatoLog.d("Start card reading", "CardState.onConnection")
        
        // Additional logging configuration for card operations
        SatoLog.d(TAG, "=== CARD CONNECTION START ===")
        SatoLog.d(TAG, "Configuring detailed logging for card operations")
        
        // Log satochip library version and capabilities
        android.util.Log.d("org.satochip.client", "SATOCHIPLIB: Card connection initiated")
        SatoLog.d(TAG, "Satochip library initialized and ready for operations")
        
        parser = cmdSet.parser

        try {
//          val respdu: APDUResponse = cmdSet.cardSelect("seedkeeper").checkOK()
            val respdu: APDUResponse = cmdSet.cardSelect("satochip").checkOK()
            val rapduStatus = cmdSet.cardGetStatus()//To update status if it's not the first reading

            cardStatus = cmdSet.applicationStatus ?: return
            cardStatus = ApplicationStatus(rapduStatus)

            SatoLog.d("testSatochip", "card status: $cardStatus")

            // check if setupDone
            // TODO: check card type and version, do setup accordingly if needed
            if (cardStatus.isSetupDone == false) {
                SatoLog.d(TAG, "CardVersionInt: ${getCardVersionInt(cardStatus)}")
                if (getCardVersionInt(cardStatus!!) <= 0x00010001) {
                    SatoLog.d(TAG, "Satodime v0.1-0.1 requires user to claim ownership to continue!")
                    return
                }
            }

            // todo: check cardtype
            testSeedkeeper()

            // get authentikey
            val respApdu = cmdSet.cardGetAuthentikey()
            // todo: get authentikey
            SatoLog.d(TAG, "authentikeyHex: $authentikeyHex")
            isCardDataAvailable = true

            SatoLog.d("Card read successfully", "CardState.onConnection")
        } catch (error: Exception) {
            SatoLog.e(TAG, "An error occurred: $error")
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    @Throws(Exception::class)
    fun testSeedkeeper() {
        SatoLog.d("testSatochip", "Start Seedkeeper tests")
        val cardStatus = cmdSet.applicationStatus ?: return
//      val pinString = "123456"
        val pinString = "qqqq"
        val pinBytes = pinString.toByteArray(Charsets.UTF_8)
        val wrongPinBytes = "0000".toByteArray(Charsets.UTF_8)
        var respApdu = APDUResponse(ByteArray(0), 0x00, 0x00)

        // applet version
//        val appletVersion = cardStatus?.protocolVersion ?: 0

        // check setup status
        if (cardStatus.isSetupDone == false) {
            try {
                respApdu = cmdSet.cardSetup(5, pinBytes) ?: respApdu
            } catch (error: Exception) {
                SatoLog.e("testSatochip", "Start Seedkeeper tests: Error: $error")
            }
        }
        // verify PIN
        cmdSet.setPin0(pinBytes)
        cmdSet.cardVerifyPIN()
        // from android 8 and above
        val startTime = Instant.now()

        when (actionType) {
            TestItems.ScanCard -> {
                testSeedkeeperMemory()
                testGenerateMasterseed()
                testGenerateRandomSecret()
                testImportExportSecretPlain()
                testImportExportSecretEncrypted()
                testBip39MnemonicV2()
                testCardGetPubkeyFromKeyslot()
                testCardBip32GetExtendedkeySeedVector2()
                testCardBip32GetExtendedkeySeedVector3()
//                testCardBip32GetExtendedkeyBip85()
                resetSecrets()
            }
            TestItems.SeedKeeperMemory -> {
                testSeedkeeperMemory()
            }
            TestItems.GenerateMasterSeed -> {
                testGenerateMasterseed()
            }
            TestItems.GenerateRandomSecret -> {
                testGenerateRandomSecret()
            }
            TestItems.ImportExportSecretPlain -> {
                testImportExportSecretPlain()
            }
            TestItems.ImportExportSecretEncrypted -> {
                testImportExportSecretEncrypted()
            }
            TestItems.Bip39MnemonicV2 -> {
                testBip39MnemonicV2()
            }
            TestItems.CardBip32GetExtendedKeySeedVector1 -> {
                testCardGetPubkeyFromKeyslot()
            }
            TestItems.CardBip32GetExtendedKeySeedVector2 -> {
                testCardBip32GetExtendedkeySeedVector2()
            }
            TestItems.CardBip32GetExtendedKeySeedVector3 -> {
                testCardBip32GetExtendedkeySeedVector3()
            }
            TestItems.CardBip32GetExtendedKeyBip85 -> {
                testCardBip32GetExtendedkeyBip85()
            }
            TestItems.ResetSecrets -> {
                resetSecrets()
            }
            TestItems.CheckAuthenticity -> {
                testAuthenticity()
            }
            TestItems.SignMessage -> {
                try {
                    SatoLog.d("testSatochip", "Executing Sign Transaction Hash test...")
                    nbTestTotal++

                    // 1. Define the message and path (Path might not be directly used by cardSignTransactionHash)
                    val message = "This is a test message to sign."
                    val messageBytes = message.toByteArray(Charsets.UTF_8)
                    val path = "m/84'/0'/0'/0/0" 

                    SatoLog.d("testSatochip", "Signing message: '$message' (Path for context: $path)")

                    // 2. Hash the message (SHA-256 recommended for 32 bytes)
                    val messageHash = MessageDigest.getInstance("SHA-256").digest(messageBytes)
                    SatoLog.d("testSatochip", "Message SHA-256 hash (hex): ${messageHash.toHexString()}")

                    // 3. Call the command set method to sign the hash
                    // Assumes key number 0 and no 2FA challenge response
                    // val keyNumber: Byte = 0
                    // val keyNumber: Byte = 1 // TODO: use keyNumber 1
                    // val keyNumber: Byte = 2
                    // val keyNumber: Byte = 3
                    val keyNumber: Byte = 0xFF.toByte()
                    val challengeResponse: ByteArray? = null
                    val signResponse: APDUResponse = cmdSet.cardSignTransactionHash(keyNumber, messageHash, challengeResponse).checkOK()

                    // 4. Process the signature
                    val signature = signResponse.data
                    SatoLog.d("testSatochip", "Message hash signed successfully! Signature (hex): ${signature.toHexString()}")

                    // 5. Update counters and status
                    nbTestSuccess++
                    resultCodeLive.postValue(NfcResultCode.Ok)

                } catch (e: Exception) {
                    SatoLog.e("testSatochip", "Sign Transaction Hash test FAILED: $e")
                    resultCodeLive.postValue(NfcResultCode.UnknownError)
                }
            }
            TestItems.SignSchnorrHash -> {
                try {
                    SatoLog.d("testSatochip", "Executing Sign Schnorr Hash test...")
                    nbTestTotal++

                    // 1. Define the message and path (Path might not be directly used by cardSignSchnorrHash)
                    val message = "This is a test message to sign with Schnorr."
                    val messageBytes = message.toByteArray(Charsets.UTF_8)
                    val path = "m/86'/0'/0'/0/0" 

                    SatoLog.d("testSatochip", "Signing message with Schnorr: '$message' (Path for context: $path)")

// I have added a 'bypass_tweak' argument since for Nostr, the private key does not use tweaking (contrary to Taproot).

// The steps are the following: 
// 1. derive a BIP32 key using cardBip32GetExtendedKey()

// byte[][] extendedKey = cmdSet.cardBip32GetExtendedKey(path);
// byte[] publicKey = extendedKey[0];
// byte[] chainCode = extendedKey[1];

// 2. bypass tweak using cardTaprootTweakPrivkey() with correct argument (Schnorr alg uses another privkey slot, that's why this call is needed even when tweak is not used)
/**
* This function tweak the currently available private stored in the Satochip.
* Tweaking is based on the 'taproot_tweak_seckey(seckey0, h)' algorithm specification defined here:
* https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
* <p>
* ins: 0x7C
* p1: key number or 0xFF for the last derived Bip32 extended key
* p2: 0x00 for key tweak, 0x01 to bypass tweak
* data: [hash(32b) | option: 2FA-flag(2b)|hmac(20b)]
* return: [sig]
*/
// tweak the bip32 key according to bip341
val keynbr: Byte = 0xFF.toByte()
val tweak: ByteArray? = null

val tweakResponse: APDUResponse = cmdSet.cardTaprootTweakPrivkey(keynbr, 0x01.toByte(), tweak)
 
// TODO: Figure out how the python library is doing this.
 
// 3. call cardSignSchnorrHash() with the hash of the message to sign

                    // 2. Hash the message (SHA-256 recommended for 32 bytes)
                    val messageHash = MessageDigest.getInstance("SHA-256").digest(messageBytes)
                    SatoLog.d("testSatochip", "Message SHA-256 hash (hex): ${messageHash.toHexString()}")

                    // 3. Call the command set method to sign the hash with Schnorr
                    // Assumes key number 0 and no 2FA challenge response
                    // val keyNumber: Byte = 0
                    // val keyNumber: Byte = 1 // TODO: use keyNumber 1
                    // val keyNumber: Byte = 2
                    // val keyNumber: Byte = 3
                    val keyNumber: Byte = 0xFF.toByte()
                    val challengeResponse: ByteArray? = null
                    val signResponse: APDUResponse = cmdSet.cardSignSchnorrHash(keyNumber, messageHash, challengeResponse).checkOK()

                    // 4. Process the signature
                    val signature = signResponse.data
                    SatoLog.d("testSatochip", "Message hash signed successfully with Schnorr! Signature (hex): ${signature.toHexString()}")

                    // 5. Update counters and status
                    nbTestSuccess++
                    resultCodeLive.postValue(NfcResultCode.Ok)

                } catch (e: Exception) {
                    SatoLog.e("testSatochip", "Sign Schnorr Hash test FAILED: $e")
                    resultCodeLive.postValue(NfcResultCode.UnknownError)
                }
            }
            TestItems.SignNostrEvent -> {
                try {
                    SatoLog.d("testSatochip", "Executing Sign Nostr Event test...")
                    SatoLog.d("testSatochip", "=== NOSTR EVENT SIGNING TEST START ===")
                    nbTestTotal++

                    // 1. Define the parameters for Nostr event signing
                    val keyslot = 0x01 // Use key number 1
                    val path = "" // Don't use path for Nostr when using key number 1
                    // val keyslot = 0xFF // Use 0xFF for the last derived BIP32 extended key
                    // val path = "m/44'/0'/0'/0/0" // BIP32 path for Bitcoin (as per documentation example)
                    // val message = "Hello from Satochip! 🚀" // Test message
                    val message = "Satochip Rocks! 🚀" // Test message
                    val kind = 1 // Text note kind

                    SatoLog.d("testSatochip", "Signing Nostr event: keyslot=$keyslot, path='$path', message='$message', kind=$kind")

                    // 2. Call the satochipSignNostrEvent function
                    // Note: PIN should already be set via cmdSet.setPin0() earlier in the flow
                    val broadcast = false // Don't broadcast for testing
                    val relay = null // No relay needed for testing
                    
                    val signedEvent: String = cmdSet.satochipSignNostrEvent(keyslot, path, message, kind, broadcast, relay)

                    // 3. Process the signed event
                    SatoLog.d("testSatochip", "Nostr event signed successfully! Signed event: $signedEvent")

                    // 4. Update counters and status
                    nbTestSuccess++
                    resultCodeLive.postValue(NfcResultCode.Ok)

                } catch (e: Exception) {
                    SatoLog.e("testSatochip", "Sign Nostr Event test FAILED: $e")
                    resultCodeLive.postValue(NfcResultCode.UnknownError)
                }
            }
            TestItems.DoNothing -> {
                SatoLog.d("testSatochip", "Do nothing test")
            }
            else -> {}
        }

        // from android 8 and above
        val endTime = Instant.now()
        // Info after tests finished
        SatoLog.d(TAG, "tests finished, total : $nbTestTotal, success: $nbTestSuccess")
        SatoLog.d(TAG, "time tests began: $startTime, time tests finished: $endTime")
        nbTestSuccess = 0
        nbTestTotal = 0

        resultCodeLive.postValue(NfcResultCode.Ok)
    }

    @Throws(Exception::class)
    fun testGenerateMasterseed() {
        SatoLog.d(TAG, "start testGenerateMasterseed")
        nbTestTotal++
        for (seedSize in 16..64 step 16) {
            SatoLog.d(TAG, "seedSize: $seedSize")

            val exportRights = SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED
            val label = "Test masterseed $seedSize export-allowed"
            val seedkeeperSecretHeader = cmdSet.seedkeeperGenerateMasterseed(
                seedSize,
                exportRights,
                label
            ) ?: continue

            // check last log
            var logs: List<SeedkeeperLog> = cmdSet.seedkeeperPrintLogs(false) ?: continue
            checkEqual(logs.size, 1, tag = "testGenerateMasterseed")
            var lastLog = logs[0]
            checkEqual(
                lastLog.ins,
                Constants.INS_GENERATE_SEEDKEEPER_MASTER_SEED,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                lastLog.sid1,
                seedkeeperSecretHeader.sid,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(lastLog.sid2, 0xFFFF, tag = "testGenerateMasterseed")
            checkEqual(lastLog.sw, StatusWord.OK.value, tag = "testGenerateMasterseed")

            // export secret and check fingerprint
            val secretObject =
                cmdSet.seedkeeperExportSecret(seedkeeperSecretHeader.sid, null)
                    ?: continue
            val exportedHeader = secretObject.secretHeader
            checkEqual(
                exportedHeader.sid,
                seedkeeperSecretHeader.sid,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.type,
                seedkeeperSecretHeader.type,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.origin,
                seedkeeperSecretHeader.origin,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.exportRights,
                seedkeeperSecretHeader.exportRights,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedHeader.fingerprintBytes,
                seedkeeperSecretHeader.fingerprintBytes,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
//            checkEqual(exportedHeader.rfu2, header.rfu2, tag = "testGenerateMasterseed")
            checkEqual(
                exportedHeader.subtype,
                seedkeeperSecretHeader.subtype,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.label,
                seedkeeperSecretHeader.label,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // check last log
            logs = cmdSet.seedkeeperPrintLogs(false) ?: continue


            checkEqual(
                logs.size,
                1,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            lastLog = logs[0]
            checkEqual(
                lastLog.ins,
                Constants.INS_EXPORT_SEEDKEEPER_SECRET,
                tag = "testGenerateMasterseed"
            )
            checkEqual(
                lastLog.sid1,
                exportedHeader.sid,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                lastLog.sid2,
                0xFFFF,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                lastLog.sw,
                StatusWord.OK.value,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // erase secret if supported
            cardStatus.cardVersionInt
            if (cardStatus.protocolVersion >= 0x0002) {
                val rapdu = cmdSet.seedkeeperResetSecret(seedkeeperSecretHeader.sid)
                    ?: continue
                checkEqual(rapdu.sw, StatusWord.OK.value, tag = "testGenerateMasterseed")
            } else {
                SatoLog.d(
                    TAG,
                    "Seedkeeper v${cardStatus?.protocolVersion}: Erasing secret not supported!"
                )
            }
        }
        nbTestSuccess++
    }

    @Throws(Exception::class)
    fun testGenerateRandomSecret() {
        //introduced in Seedkeeper v0.2
        if ((cardStatus.protocolVersion ?: 0) < 0x0002) {
            SatoLog.d(
                TAG,
                "Seedkeeper v${cardStatus.protocolVersion}:" +
                        " generate random_secret with external entropy not supported!"
            )
            return
        }
        nbTestTotal++
        val pwSizes = listOf(16, 32, 48, 64)
        for (size in pwSizes) {
            val stype = SeedkeeperSecretType.MASTER_PASSWORD // 0x91 Master Password
            val exportRights =
                SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED // 0x01 Plaintext export allowed
            val subtype: Byte = 0x00 // default
            val label = "Test MasterPassword Size: $size"

            // random entropy as ascii text
            val entropy = randomBytes(size)
            val saveEntropy = true

            // generate on card
            val seedkeeperSecretHeaders = cmdSet.seedkeeperGenerateRandomSecret(
                stype,
                subtype,
                size.toByte(),
                saveEntropy,
                entropy,
                exportRights,
                label
            ) ?: continue

            // export master password in plaintext
            val secretHeader = seedkeeperSecretHeaders[0]
            val secretObject = cmdSet.seedkeeperExportSecret(secretHeader.sid, null) ?: continue
            var exportedHeader = secretObject.secretHeader
            checkEqual(
                exportedHeader.sid,
                secretHeader.sid,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.type,
                secretHeader.type,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.origin,
                secretHeader.origin,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.exportRights,
                secretHeader.exportRights,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedHeader.fingerprintBytes,
                secretHeader.fingerprintBytes,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            // todo: not being used atm
//            checkEqual(
//                exportedHeader.rfu2,
//                secretHeader.rfu2,
//                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
//            )
            checkEqual(
                exportedHeader.subtype,
                secretHeader.subtype,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.label,
                secretHeader.label,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // test master password fingerprint
            checkByteArrayEqual(
                secretObject.getFingerprintFromSecret(),
                secretHeader.fingerprintBytes,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // check last log
            var logs = cmdSet.seedkeeperPrintLogs(false) ?: continue
            checkEqual(
                logs.size,
                1,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            var lastLog = logs[0]
            checkEqual(
                lastLog.ins,
                Constants.INS_EXPORT_SEEDKEEPER_SECRET,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                lastLog.sid1,
                exportedHeader.sid,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                lastLog.sid2,
                0xFFFF,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                lastLog.sw,
                StatusWord.OK.value,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )
        }
        nbTestSuccess++
    }


    fun testImportExportSecretPlain() {
        SatoLog.d(TAG, "start testImportExportSecretPlain")
        nbTestTotal++

        val bip39_12 = generateMnemonic(128)
        val bip39_18 = generateMnemonic(192)
        val bip39_24 = generateMnemonic(256)
        val bip39s = listOf(bip39_12, bip39_18, bip39_24)

        for (index in bip39s.indices) {
            val bip39String = bip39s[index]
            SatoLog.d(TAG, "first item: $bip39String")

            val secretBytes: ByteArray =
                byteArrayOf(bip39String.toByteArray().size.toByte()) + bip39String.toByteArray()
            SatoLog.d(TAG, "first secretBytes: ${secretBytes.size}")

            val secretFingerprintBytes = SeedkeeperSecretHeader.getFingerprintBytes(secretBytes)

            SatoLog.d(TAG, "first secretFingerprintBytes: $secretFingerprintBytes")

            val label = "Test BIP39 size:${12 + index * 6}"
            val secretHeader = SeedkeeperSecretHeader(
                0,
                SeedkeeperSecretType.BIP39_MNEMONIC,
                0x00.toByte(),
                SeedkeeperSecretOrigin.PLAIN_IMPORT,
                SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED,
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                secretFingerprintBytes,
                label
            )
            SatoLog.d(TAG, "first header: $secretFingerprintBytes")

            val secretObject =
                SeedkeeperSecretObject(secretBytes, secretHeader, false, null)
            SatoLog.d(
                TAG,
                "first secretObject: $secretObject, ${secretObject.secretHeader.fingerprintBytes.size}"
            )

            val seedkeeperSecretImportHeader = cmdSet.seedkeeperImportSecret(secretObject)
            SatoLog.d(TAG, "first seedkeeperImportSecretResult: $seedkeeperSecretImportHeader")

//            checkEqual(
//                seedkeeperImportSecretResult.apduResponse.sw,
//                StatusWord.OK.value,
//                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
//            )
            checkByteArrayEqual(
                seedkeeperSecretImportHeader.fingerprintBytes,
                secretFingerprintBytes,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // export secret
            val exportedSecretObject =
                cmdSet.seedkeeperExportSecret(seedkeeperSecretImportHeader.sid, null)
            val exportedSecretHeader = exportedSecretObject.secretHeader
            checkEqual(
                exportedSecretHeader.type,
                secretHeader.type,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedSecretHeader.subtype,
                secretHeader.subtype,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedSecretHeader.origin,
                secretHeader.origin,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedSecretHeader.exportRights,
                secretHeader.exportRights,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedSecretHeader.fingerprintBytes,
                secretHeader.fingerprintBytes,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )
//            checkEqual(
//                exportedSecretHeader.rfu2,
//                secretHeader.rfu2,
//                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
//            )
            checkEqual(
                exportedSecretHeader.label,
                secretHeader.label,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedSecretObject.secretBytes,
                exportedSecretObject.secretBytes,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // todo: test logging

            // erase secret if supported
            if (cardStatus.protocolVersion >= 0x0002) {
                var rapdu = cmdSet.seedkeeperResetSecret(exportedSecretHeader.sid)
                checkEqual(
                    rapdu.sw,
                    StatusWord.OK.value,
                    "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
                )
            } else {
                SatoLog.d(
                    TAG,
                    "Seedkeeper v${cardStatus.protocolVersion}: Erasing secret not supported!"
                )
            }
        }
        nbTestSuccess++
    }

    @Throws(Exception::class)
    fun testSeedkeeperMemory() {
        // WARNING: this test will fill all the card available memory
        SatoLog.d(TAG, "start testSeedkeeperMemory")
        nbTestTotal++

        // introduced in Seedkeeper v0.2
        if (cardStatus.protocolVersion < 0x0002) {
            SatoLog.d(
                TAG,
                "testSeedkeeperMemory: Seedkeeper v${cardStatus.protocolVersion}: delete secret not supported!!"
            )
            return
        }

        val sids = mutableListOf<Int>()
        val secrets = mutableListOf<SeedkeeperSecretObject>()
        val fingerprints = mutableListOf<String>()

        var secretSize = 1
        while (true) {
            SatoLog.d(TAG, "secretSize: $secretSize")
            val secretBytes = byteArrayOf(
                (secretSize shr 8).toByte(),
                (secretSize and 0xFF).toByte()
            ) + randomBytes(secretSize)

            // make header
            val secretFingerprintBytes = SeedkeeperSecretHeader.getFingerprintBytes(secretBytes)
            val label = "Test Data with ${secretSize + 2} bytes"
            val secretHeader = SeedkeeperSecretHeader(
                0,
                SeedkeeperSecretType.DATA,
                0x00.toByte(),
                SeedkeeperSecretOrigin.PLAIN_IMPORT,
                SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED,
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                secretFingerprintBytes,
                label
            )

            val secretObject = SeedkeeperSecretObject(
                secretBytes,
                secretHeader,
                false,
                null
            )
            // import secret
            try {
                val seedkeeperSecretHeader = cmdSet.seedkeeperImportSecret(
                        secretObject
                    )
                checkByteArrayEqual(
                    seedkeeperSecretHeader.fingerprintBytes,
                    secretFingerprintBytes,
                    tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
                )
                sids.add(seedkeeperSecretHeader.sid)
                secrets.add(secretObject)
                fingerprints.add(seedkeeperSecretHeader.fingerprintBytes.toString())
            } catch (error: Exception) {
                SatoLog.e(TAG, "An error occurred: $error")
                break
            }

            // status todo: new class to hold these values?
            val seedkeeperStatus = cmdSet.seedkeeperGetStatus()
            SatoLog.d(TAG, "seedkeeperStatus is successful: ${seedkeeperStatus}")
            secretSize += 1
        }

        // erase secrets from memory
        for (index in sids.indices) {
            SatoLog.d(TAG, "delete object: ${index + 1} out of ${sids.size}")
            val sid = sids[index]
            val secretObject = secrets[index]
            val secretHeader = secretObject.secretHeader

            // export secret
            val exportedSecretObject = cmdSet.seedkeeperExportSecret(sid, null)
            val exportedSecretHeader = exportedSecretObject.secretHeader
            checkEqual(
                exportedSecretHeader.type,
                secretHeader.type,
                tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedSecretHeader.subtype,
                secretHeader.subtype,
                tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedSecretHeader.origin,
                secretHeader.origin,
                tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedSecretHeader.exportRights,
                secretHeader.exportRights,
                tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedSecretHeader.fingerprintBytes,
                secretHeader.fingerprintBytes,
                tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
            )
//            checkEqual(
//                exportedSecretHeader.rfu2,
//                secretHeader.rfu2,
//                tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
//            )
            checkEqual(
                exportedSecretHeader.label,
                secretHeader.label,
                tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedSecretObject.secretBytes,
                secretObject.secretBytes,
                tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // delete object
            val rapdu = cmdSet.seedkeeperResetSecret(sid)
            checkEqual(
                rapdu.sw,
                StatusWord.OK.value,
                tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
            )
        }

        // final status
        val seedkeeperStatus = cmdSet.seedkeeperGetStatus()
        SatoLog.d(TAG, "seedkeeperStatus is successful: ${seedkeeperStatus}")
        nbTestSuccess++
    }

    fun resetSecrets() {
        nbTestTotal++
        SatoLog.d(TAG, "Start resetSecrets")
        val headers: List<SeedkeeperSecretHeader> = cmdSet.seedkeeperListSecretHeaders()
        for (header in headers) {
            SatoLog.d(TAG, "resetSecrets Header sid: ${header.sid} comencing deletion")

            val rapdu = cmdSet.seedkeeperResetSecret(header.sid)
            checkEqual(
                rapdu.sw,
                StatusWord.OK.value,
                tag = "Function: resetSecrets, line: ${Exception().stackTrace[0].lineNumber}"
            )
            SatoLog.d(TAG, "resetSecrets Header sid: ${header.sid} delete successful")
        }
        nbTestSuccess++
    }

    fun testImportExportSecretEncrypted() {
        nbTestTotal++
        SatoLog.d(TAG, "Start testImportExportSecretEncrypted")
        try {
            // Get authentikey then import it in plaintext
            val authentikeyBytes = cmdSet.cardGetAuthentikey()
            val authentikeySecretBytes = ByteArray(authentikeyBytes.size + 1)
            authentikeySecretBytes[0] = authentikeyBytes.size.toByte()
            System.arraycopy(
                authentikeyBytes,
                0,
                authentikeySecretBytes,
                1,
                authentikeyBytes.size
            )

            val authentikeyFingerprintBytes =
                SeedkeeperSecretHeader.getFingerprintBytes(authentikeySecretBytes)
            val authentikeyLabel = "Test Seedkeeper own kauthentikey"
            // todo: maybe issue
            val authentikeySecretHeader = SeedkeeperSecretHeader(
                0,
                SeedkeeperSecretType.PUBKEY,
                0x00.toByte(),
                SeedkeeperSecretOrigin.PLAIN_IMPORT,
                SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED,
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                authentikeyFingerprintBytes,
                authentikeyLabel
            )
            val authentikeySecretObject = SeedkeeperSecretObject(
                authentikeySecretBytes,
                authentikeySecretHeader,
                false,
                null
            )

            // Import secret
            val seedkeeperSecretHeader = cmdSet.seedkeeperImportSecret(authentikeySecretObject)
            checkByteArrayEqual(
                seedkeeperSecretHeader.fingerprintBytes,
                authentikeyFingerprintBytes,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // Export the authentikey
            val exportedAuthentikeySecretObject =
                cmdSet.seedkeeperExportSecret(seedkeeperSecretHeader.sid, null)
            val exportedAuthentikeySecretHeader = exportedAuthentikeySecretObject.secretHeader
            checkEqual(
                exportedAuthentikeySecretHeader.type,
                authentikeySecretHeader.type,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedAuthentikeySecretHeader.subtype,
                authentikeySecretHeader.subtype,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedAuthentikeySecretHeader.origin,
                authentikeySecretHeader.origin,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedAuthentikeySecretHeader.exportRights,
                authentikeySecretHeader.exportRights,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedAuthentikeySecretHeader.fingerprintBytes,
                authentikeySecretHeader.fingerprintBytes,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )
//            checkEqual(
//                exportedAuthentikeySecretHeader.rfu2,
//                authentikeySecretHeader.rfu2,
//                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
//            )
            checkEqual(
                exportedAuthentikeySecretHeader.label,
                authentikeySecretHeader.label,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedAuthentikeySecretObject.secretBytes,
                authentikeySecretObject.secretBytes,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // Generate MasterSeed and export encrypted
            val seedSizes = listOf(16, 32, 48, 64)
            for (size in seedSizes) {
                // Generate masterseed on card
                val masterseedExportRights = SeedkeeperExportRights.EXPORT_ENCRYPTED_ONLY
                val masterseedLabel = "Test masterseed $size bytes export-encrypted"
                val seedkeeperMasterSeedResult = cmdSet.seedkeeperGenerateMasterseed(
                        size,
                        masterseedExportRights,
                        masterseedLabel
                    )

                // Check last log
                var logs = cmdSet.seedkeeperPrintLogs(false)
                checkEqual(
                    logs.size,
                    1,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                var lastLog = logs[0]
                checkEqual(
                    lastLog.ins,
                    Constants.INS_GENERATE_SEEDKEEPER_MASTER_SEED,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sid1,
                    seedkeeperMasterSeedResult.sid,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sid2,
                    0xFFFF,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sw,
                    StatusWord.OK.value,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )

                // Export secret in plaintext => should fail given the export rights
                try {
                    val exportedMasterseedObject =
                        cmdSet.seedkeeperExportSecret(
                            seedkeeperMasterSeedResult.sid,
                            null
                        )
                    // force fail if it does not throw
                    checkEqual(
                        true,
                        false,
                        "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                    )
                } catch (error: Exception) {
                    SatoLog.d(TAG, "Failed to export secret in plaintext (not allowed by policy): $error")
                }

                // Test logs for fail
                val logResult = cmdSet.seedkeeperPrintLogs(false)
                logs = logResult
                //todo: create an object for total logs and available logs
//                nbTotalLogs = logResult.nbTotalLogs
//                nbAvailLogs = logResult.nbAvailLogs
                checkEqual(
                    logs.size,
                    1,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                lastLog = logs[0]
                checkEqual(
                    lastLog.ins,
                    Constants.INS_EXPORT_SEEDKEEPER_SECRET,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sid1,
                    seedkeeperMasterSeedResult.sid,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sid2,
                    0xFFFF,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sw,
                    StatusWord.EXPORT_NOT_ALLOWED.value,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )

                // Export it encrypted
                val exportedMasterseedObject =
                    cmdSet.seedkeeperExportSecret(
                        seedkeeperMasterSeedResult.sid,
                        seedkeeperSecretHeader.sid
                    )
                val exportedMasterseedHeader = exportedMasterseedObject.secretHeader
                checkEqual(
                    exportedMasterseedHeader.type,
                    seedkeeperMasterSeedResult.type,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    exportedMasterseedHeader.subtype,
                    seedkeeperMasterSeedResult.subtype,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    exportedMasterseedHeader.origin,
                    seedkeeperMasterSeedResult.origin,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    exportedMasterseedHeader.exportRights,
                    seedkeeperMasterSeedResult.exportRights,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkByteArrayEqual(
                    exportedMasterseedHeader.fingerprintBytes,
                    seedkeeperMasterSeedResult.fingerprintBytes,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
//                checkEqual(
//                    exportedMasterseedHeader.rfu2,
//                    masterseedHeader.rfu2,
//                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
//                )
                checkEqual(
                    exportedMasterseedHeader.label,
                    seedkeeperMasterSeedResult.label,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )

                // Check last log
                val logResult2 = cmdSet.seedkeeperPrintLogs(false)
                logs = logResult2
                //todo
//                nbTotalLogs = logResult2.nbTotalLogs
//                nbAvailLogs = logResult2.nbAvailLogs
                checkEqual(
                    logs.size,
                    1,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                lastLog = logs[0]
                checkEqual(
                    lastLog.ins,
                    Constants.INS_EXPORT_SEEDKEEPER_SECRET,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sid1,
                    seedkeeperMasterSeedResult.sid,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sid2,
                    seedkeeperSecretHeader.sid,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sw,
                    StatusWord.OK.value,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )

                // Reimport it encrypted then check if fingerprints match
                val seedkeeperImportSecretResult2 = cmdSet.seedkeeperImportSecret(
                        exportedMasterseedObject
                    )

                checkByteArrayEqual(
                    seedkeeperImportSecretResult2.fingerprintBytes,
                    seedkeeperMasterSeedResult.fingerprintBytes,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )

                // Check logs
                val logResult3 = cmdSet.seedkeeperPrintLogs(false)
                logs = logResult3
//                nbTotalLogs = logResult3.nbTotalLogs
//                nbAvailLogs = logResult3.nbAvailLogs
                checkEqual(
                    logs.size,
                    1,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                lastLog = logs[0]
                checkEqual(
                    lastLog.ins,
                    Constants.INS_IMPORT_SEEDKEEPER_SECRET,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sid1,
                    seedkeeperImportSecretResult2.sid,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sid2,
                    seedkeeperSecretHeader.sid,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sw,
                    StatusWord.OK.value,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )

                // Erase secret if supported
                if (cardStatus.protocolVersion >= 0x0002) {
                    var rapdu =
                        cmdSet.seedkeeperResetSecret(seedkeeperMasterSeedResult.sid)
                    checkEqual(
                        rapdu.sw,
                        StatusWord.OK.value,
                        "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                    )
                    rapdu = cmdSet.seedkeeperResetSecret(seedkeeperImportSecretResult2.sid)
                    checkEqual(
                        rapdu.sw,
                        StatusWord.OK.value,
                        "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                    )
                } else {
                    SatoLog.d(
                        TAG,
                        "Seedkeeper v${cardStatus.protocolVersion}: Erasing secret not supported!"
                    )
                }
            }

            // Erase authentikey (if supported)
            if (cardStatus.protocolVersion >= 0x0002) {
                val rapdu = cmdSet.seedkeeperResetSecret(seedkeeperSecretHeader.sid)
                checkEqual(
                    rapdu.sw,
                    StatusWord.OK.value,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
            } else {
                SatoLog.d(
                    TAG,
                    "Seedkeeper v${cardStatus.protocolVersion}: Erasing secret not supported!"
                )
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        nbTestSuccess++
    }

    fun testBip39MnemonicV2() {
        if ((cardStatus.protocolVersion ?: 0) < 0x0002) {
            SatoLog.d(
                TAG,
                "Seedkeeper v${cardStatus.protocolVersion}:" +
                        " generate random_secret with external entropy not supported!"
            )
            return
        }
        nbTestTotal++
        SatoLog.d(TAG, "Start testBip39MnemonicV2")
        val entropySizes = listOf(128, 192, 256)
        val passphrases = listOf("", "", "IveComeToTalkWithYouAgain")

        for (index in entropySizes.indices) {
            val entropySize = entropySizes[index]
            val entropy = ByteArray(entropySize / 8)
            java.security.SecureRandom().nextBytes(entropy)
            SatoLog.d(TAG, "randomEntropyHex is $entropy")

            val bip39String = MnemonicCode.INSTANCE.toMnemonic(entropy).joinToString(" ")
            SatoLog.d(TAG, "bip39String is $bip39String")

            val entropyBytes = MnemonicCode.INSTANCE.toEntropy(stringToList(bip39String))
            SatoLog.d(TAG, "entropyBytes is $entropyBytes")

            checkByteArrayEqual(
                entropyBytes,
                entropy,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )

            val passphrase = passphrases[index]
            val passphraseBytes = passphrase.toByteArray(Charsets.UTF_8)
            val masterseedBytes = MnemonicCode.toSeed(stringToList(bip39String), passphrase)
            val secretBytes = byteArrayOf(masterseedBytes.size.toByte()) + masterseedBytes +
                    byteArrayOf(0x00.toByte()) +
                    byteArrayOf(entropyBytes.size.toByte()) + entropyBytes +
                    byteArrayOf(passphraseBytes.size.toByte()) + passphraseBytes

            val secretFingerprintBytes = SeedkeeperSecretHeader.getFingerprintBytes(secretBytes)
            val label = "Test BIP39 size: ${12 + index * 6}"

            val secretHeader = SeedkeeperSecretHeader(
                0,
                SeedkeeperSecretType.MASTERSEED,
                0x01.toByte(),
                SeedkeeperSecretOrigin.PLAIN_IMPORT,
                SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED,
                0x00.toByte(),
                0x00.toByte(),
                0x00.toByte(),
                secretFingerprintBytes,
                label
            )
            val secretObject = SeedkeeperSecretObject(
                secretBytes,
                secretHeader,
                false,
                null
            )

            // Import secret
            val seedkeeperImportSecretResult = cmdSet.seedkeeperImportSecret(secretObject)

            checkByteArrayEqual(
                seedkeeperImportSecretResult.fingerprintBytes,
                secretFingerprintBytes,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )
            // Export secret
            val exportedSecretObject =
                cmdSet.seedkeeperExportSecret(seedkeeperImportSecretResult.sid, null)
            val exportedSecretHeader = exportedSecretObject.secretHeader
            checkEqual(
                exportedSecretHeader.type,
                secretHeader.type,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedSecretHeader.subtype,
                secretHeader.subtype,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedSecretHeader.origin,
                secretHeader.origin,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedSecretHeader.exportRights,
                secretHeader.exportRights,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedSecretHeader.fingerprintBytes,
                secretHeader.fingerprintBytes,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )
//            checkEqual(
//                exportedSecretHeader.rfu2,
//                secretHeader.rfu2,
//                "Function: ${::testBip39MnemonicV2.name}, line: ${Exception().stackTrace[0].lineNumber}"
//            )
            checkEqual(
                exportedSecretHeader.label,
                secretHeader.label,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedSecretObject.secretBytes,
                secretObject.secretBytes,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // Erase secret if supported
            if (cardStatus.protocolVersion >= 0x0002) {
                val rapdu = cmdSet.seedkeeperResetSecret(exportedSecretHeader.sid)
                checkEqual(
                    rapdu.sw,
                    StatusWord.OK.value,
                    "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
                )
            } else {
                SatoLog.d(
                    TAG,
                    "Seedkeeper v${cardStatus.protocolVersion}: Erasing secret not supported!"
                )
            }
        }
        nbTestSuccess++
    }

    fun testCardGetPubkeyFromKeyslot() {
        nbTestTotal++
        SatoLog.d(TAG, "Start testCardGetPubkeyFromKeyslot")
        SatoLog.d(TAG, "=== PUBKEY TEST START ===")

        try {
            // 1. Define the keyslot parameter
            val keyslot = 1 // Use keyslot 1 as requested

            SatoLog.d(TAG, "Getting public key from keyslot: $keyslot")

            // 2. Call the cardGetPubkeyFromKeyslot function
            SatoLog.d(TAG, "About to call cardGetPubkeyFromKeyslot with keyslot: $keyslot, shortFormat: false")
            val publicKey: ByteArray = cmdSet.cardGetPubkeyFromKeyslot(keyslot,false)
            SatoLog.d(TAG, "cardGetPubkeyFromKeyslot returned ${publicKey.size} bytes")
            
            // 3. Remove first 2 bytes and extract next 64 hex characters
            val publicKeyWithoutHeader = publicKey.copyOfRange(2, publicKey.size)
            val publicKeyHex = publicKeyWithoutHeader.toHexString()
            val publicKey64Chars = if (publicKeyHex.length >= 64) publicKeyHex.substring(0, 64) else publicKeyHex
            
            SatoLog.d(TAG, "Public key retrieved successfully! Public key (hex): ${publicKey.toHexString()}")
            SatoLog.d(TAG, "Public key without header (hex): $publicKeyHex")
            SatoLog.d(TAG, "Public key first 64 chars: $publicKey64Chars")

            SatoLog.d(TAG, "About to call cardGetPubkeyFromKeyslot with keyslot: $keyslot, shortFormat: true")
            val publicKeyS: ByteArray = cmdSet.cardGetPubkeyFromKeyslot(keyslot,true)
            SatoLog.d(TAG, "cardGetPubkeyFromKeyslot (short) returned ${publicKeyS.size} bytes")
            val publicKeySHex = publicKeyS.toHexString()
            SatoLog.d(TAG, "Public key short: $publicKeySHex")

            // 4. Update counters and status
            nbTestSuccess++
            resultCodeLive.postValue(NfcResultCode.Ok)

        } catch (e: Exception) {
            SatoLog.e(TAG, "Get public key from keyslot test FAILED: $e")
            resultCodeLive.postValue(NfcResultCode.UnknownError)
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun testCardBip32GetExtendedkeySeedVector2() {
        nbTestTotal++
        SatoLog.d(TAG, "Start testCardBip32GetExtendedkeySeedVector2")

        // introduced in Seedkeeper v0.2
        if (cardStatus.protocolVersion < 0x0002) {
            SatoLog.d(TAG, "testCardBip32GetExtendedkeySeedVector2: BIP32 derivation not supported!")
            return
        }

        // create a secret
        val masterseedHex =
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        val masterseedBytes = masterseedHex.hexToByteArray()
        val secretBytes = byteArrayOf(masterseedBytes.size.toByte()) + masterseedBytes

        val secretFingerprintBytes = SeedkeeperSecretHeader.getFingerprintBytes(secretBytes)
        val label = "Test Masterseed BIP32 vector2"

        val secretHeader = SeedkeeperSecretHeader(
            0,
            SeedkeeperSecretType.MASTERSEED,
            0x00.toByte(),
            SeedkeeperSecretOrigin.PLAIN_IMPORT,
            SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED,
            0x00.toByte(),
            0x00.toByte(),
            0x00.toByte(),
            secretFingerprintBytes,
            label
        )
        val secretObject = SeedkeeperSecretObject(
            secretBytes,
            secretHeader,
            false,
            null
        )
        // import secret
        val seedkeeperImportSecretResult = cmdSet.seedkeeperImportSecret(secretObject)

        checkByteArrayEqual(
            seedkeeperImportSecretResult.fingerprintBytes,
            secretFingerprintBytes,
            "Function: testCardBip32GetExtendedkeySeedVector2, line: ${Exception().stackTrace[0].lineNumber}"
        )

        val paths = arrayOf(
            "m",
            "m/0",
            "m/0/2147483647'",
            "m/0/2147483647'/1",
            "m/0/2147483647'/1/2147483646'",
            "m/0/2147483647'/1/2147483646'/2"
        )
        val xpubs = arrayOf(
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        )
        // test xpub
        for (i in paths.indices) {
            SatoLog.d(TAG, "testCardBip32GetExtendedkeySeedVector2 Xpub Derivation $i")
            val path = paths[i]
            val xpub = cmdSet.cardBip32GetXpub(path, 0x0488b21e, seedkeeperImportSecretResult.sid)
            checkEqual(
                xpub,
                xpubs[i],
                "Function: testCardBip32GetExtendedkeySeedVector2, line: ${Exception().stackTrace[0].lineNumber}"
            )
        }
        // delete seed
        val respdu = cmdSet.seedkeeperResetSecret(seedkeeperImportSecretResult.sid)
        checkEqual(
            respdu.sw,
            StatusWord.OK.value,
            "Function: testCardBip32GetExtendedkeySeedVector2, line: ${Exception().stackTrace[0].lineNumber}"
        )
        nbTestSuccess++
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun testCardBip32GetExtendedkeySeedVector3() {
        nbTestTotal++
        SatoLog.d(TAG, "Start testCardBip32GetExtendedkeySeedVector3")

        // introduced in Seedkeeper v0.2
        if (cardStatus.protocolVersion < 0x0002) {
            SatoLog.d(TAG, "testCardBip32GetExtendedkeySeedVector3: BIP32 derivation not supported!")
            return
        }

        // create a secret
        val masterseedHex =
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
        val masterseedBytes = masterseedHex.hexToByteArray()
        val secretBytes = byteArrayOf(masterseedBytes.size.toByte()) + masterseedBytes

        val secretFingerprintBytes = SeedkeeperSecretHeader.getFingerprintBytes(secretBytes)
        val label = "Test Masterseed BIP32 vector3"

        val secretHeader = SeedkeeperSecretHeader(
            0,
            SeedkeeperSecretType.MASTERSEED,
            0x00.toByte(),
            SeedkeeperSecretOrigin.PLAIN_IMPORT,
            SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED,
            0x00.toByte(),
            0x00.toByte(),
            0x00.toByte(),
            secretFingerprintBytes,
            label
        )
        val secretObject = SeedkeeperSecretObject(
            secretBytes,
            secretHeader,
            false,
            null
        )
        // import secret
        val seedkeeperImportSecretResult = cmdSet.seedkeeperImportSecret(secretObject)

        checkByteArrayEqual(
            seedkeeperImportSecretResult.fingerprintBytes,
            secretFingerprintBytes,
            "Function: testCardBip32GetExtendedkeySeedVector3, line: ${Exception().stackTrace[0].lineNumber}"
        )

        val paths = arrayOf(
            "m",
            "m/0'",
        )
        val xpubs = arrayOf(
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
        )
        // test xpub
        for (i in paths.indices) {
            SatoLog.d(TAG, "testCardBip32GetExtendedkeySeedVector3 Xpub Derivation $i")
            val path = paths[i]
            val xpub = cmdSet.cardBip32GetXpub(path, 0x0488b21e, seedkeeperImportSecretResult.sid)
            checkEqual(
                xpub,
                xpubs[i],
                "Function: testCardBip32GetExtendedkeySeedVector3, line: ${Exception().stackTrace[0].lineNumber}"
            )
        }
        // delete seed
        val respdu = cmdSet.seedkeeperResetSecret(seedkeeperImportSecretResult.sid)
        checkEqual(
            respdu.sw,
            StatusWord.OK.value,
            "Function: testCardBip32GetExtendedkeySeedVector3, line: ${Exception().stackTrace[0].lineNumber}"
        )
        nbTestSuccess++
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun testCardBip32GetExtendedkeyBip85() {
        nbTestTotal++
        SatoLog.d(TAG, "Start testCardBip32GetExtendedkeyBip85")

        // introduced in Seedkeeper v0.2
        if (cardStatus.protocolVersion < 0x0002) {
            SatoLog.d(TAG, "testCardBip32GetExtendedkeyBip85: BIP32 derivation not supported!")
            return
        }

        val bip39 =
            "panel rally element develop cloud diamond brother rack scale path burger arctic"
        val masterseedHex =
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
        val masterseedBytes = masterseedHex.hexToByteArray()
        val bip39bip85 =
            "devote sheriff detail immense current online clown letter loop spread weasel filter"
        val path = "m/83696968'/39'/0'/12'/0'"

        val entropyBytes = MnemonicCode.INSTANCE.toEntropy(stringToList(bip39))
        SatoLog.d(TAG, "testCardBip32GetExtendedkeyBip85: entropyHex: ${entropyBytes.toHexString()}")
        val passphraseBytes = ByteArray(0)

        var secretBytes = byteArrayOf(masterseedBytes.size.toByte()) + masterseedBytes
        secretBytes += byteArrayOf(0x00)
        secretBytes += byteArrayOf(entropyBytes.size.toByte()) + entropyBytes
        secretBytes += byteArrayOf(passphraseBytes.size.toByte()) + passphraseBytes

        val secretFingerprintBytes = SeedkeeperSecretHeader.getFingerprintBytes(secretBytes)
        val label = "Test BIP39 for BIP85 size: 12"
        val secretHeader = SeedkeeperSecretHeader(
            0,
            SeedkeeperSecretType.MASTERSEED,
            0x01.toByte(),
            SeedkeeperSecretOrigin.PLAIN_IMPORT,
            SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED,
            0x00.toByte(),
            0x00.toByte(),
            0x00.toByte(),
            secretFingerprintBytes,
            label
        )


        val secretObject = SeedkeeperSecretObject(
            secretBytes,
            secretHeader,
            false,
            null
        )

        // import secret
        val seedkeeperImportSecretResult = cmdSet.seedkeeperImportSecret(secretObject)
        checkByteArrayEqual(
            seedkeeperImportSecretResult.fingerprintBytes,
            secretFingerprintBytes,
            "Function: testCardBip32GetExtendedkeyBip85"
        )

        // export secret
        val exportedSecretObject =
            cmdSet.seedkeeperExportSecret(seedkeeperImportSecretResult.sid, null)
        val exportedSecretHeader = exportedSecretObject.secretHeader
        checkEqual(
            exportedSecretHeader.type,
            secretHeader.type,
            "Function: testCardBip32GetExtendedkeyBip85"
        )
        checkEqual(
            exportedSecretHeader.subtype,
            secretHeader.subtype,
            "Function: testCardBip32GetExtendedkeyBip85"
        )
        checkEqual(
            exportedSecretHeader.origin,
            secretHeader.origin,
            "Function: testCardBip32GetExtendedkeyBip85"
        )
        checkEqual(
            exportedSecretHeader.exportRights,
            secretHeader.exportRights,
            "Function: testCardBip32GetExtendedkeyBip85"
        )
        checkByteArrayEqual(
            exportedSecretHeader.fingerprintBytes,
            secretHeader.fingerprintBytes,
            "Function: testCardBip32GetExtendedkeyBip85"
        )
//        checkEqual(
//            exportedSecretHeader.rfu2,
//            secretHeader.rfu2,
//            "Function: testCardBip32GetExtendedkeyBip85"
//        )
        checkEqual(
            exportedSecretHeader.label,
            secretHeader.label,
            "Function: testCardBip32GetExtendedkeyBip85"
        )
        checkByteArrayEqual(
            exportedSecretObject.secretBytes,
            secretObject.secretBytes,
            "Function: testCardBip32GetExtendedkeyBip85"
        )

        // test BIP85 derivation on card
        val apduResponse = cmdSet.cardBip32GetExtendedKey(
            path,
            0x04.toByte(),
            exportedSecretHeader.sid
        )
        SatoLog.d(
            TAG,
            "testCardBip32GetExtendedkeyBip85: bip85EntropyBytes:  ${cmdSet.extendedKey.toHexString()}"
        )

        val bip85EntropyBytes = cmdSet.extendedKey.copyOfRange(0, 16)
        SatoLog.d(
            TAG,
            "testCardBip32GetExtendedkeyBip85: bip85EntropyBytes: ${bip85EntropyBytes.toHexString()}"
        )

        val bip39FromBip85 = MnemonicCode.INSTANCE.toMnemonic(bip85EntropyBytes)
        SatoLog.d(TAG, "testCardBip32GetExtendedkeyBip85: bip39Frombip85: $bip39FromBip85")
        checkEqual(
            bip39FromBip85.joinToString(separator = " "),
            bip39bip85,
            "Function: testCardBip32GetExtendedkeyBip85"
        )

        // delete masterseed
        val rapdu = cmdSet.seedkeeperResetSecret(seedkeeperImportSecretResult.sid)
        checkEqual(rapdu.sw, StatusWord.OK.value, "Function: testCardBip32GetExtendedkeyBip85")
        nbTestSuccess++
    }

    @Throws(Exception::class)
    fun testAuthenticity() {
        SatoLog.d(TAG, "start testAuthenticity")
        nbTestTotal++

        // check Card authenticity
        try {
            var authResults = cmdSet.cardVerifyAuthenticity()
            if (authResults != null) {
                if (authResults[0].compareTo("OK") == 0) {
                    authenticityStatus.postValue(AuthenticityStatus.Authentic)
                    SatoLog.d(TAG, "card authenticated successfully!")     // issue here.
                } else {
                    authenticityStatus.postValue(AuthenticityStatus.NotAuthentic)
                    SatoLog.e(TAG, "readCard failed to authenticate card!")     // issue here.
                }
                certificateList.postValue(authResults.toMutableList())
            }
        } catch (e: Exception) {
            SatoLog.e(TAG, "Failed to authenticate card with error: $e")
        }
    }
}
