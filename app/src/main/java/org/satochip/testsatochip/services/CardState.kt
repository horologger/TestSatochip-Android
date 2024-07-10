package org.satochip.testsatochip.services

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.lifecycle.MutableLiveData
import org.bitcoinj.crypto.MnemonicCode
import org.satochip.android.NFCCardManager
import org.satochip.client.ApplicationStatus
import org.satochip.client.AuthentikeyObject
import org.satochip.client.Constants
import org.satochip.client.SatochipCommandSet
import org.satochip.client.SatochipParser
import org.satochip.client.seedkeeper.SeedkeeperExportRights
import org.satochip.client.seedkeeper.SeedkeeperImportSecretResult
import org.satochip.client.seedkeeper.SeedkeeperLog
import org.satochip.client.seedkeeper.SeedkeeperMasterSeedResult
import org.satochip.client.seedkeeper.SeedkeeperSecretHeader
import org.satochip.client.seedkeeper.SeedkeeperSecretObject
import org.satochip.client.seedkeeper.SeedkeeperSecretOrigin
import org.satochip.client.seedkeeper.SeedkeeperSecretType
import org.satochip.client.seedkeeper.SeedkeeperStatus
import org.satochip.client.seedkeeper.StatusWord
import org.satochip.io.APDUResponse
import org.satochip.testsatochip.data.AuthenticityStatus
import org.satochip.testsatochip.data.NfcActionType
import org.satochip.testsatochip.data.NfcResultCode
import java.time.Instant

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
    var actionType: NfcActionType = NfcActionType.DoNothing
    var actionIndex: Int = 0

    var isConnected =
        MutableLiveData(false) // the app is connected to a card // updated in SatochipCardListener


    fun initialize(cmdSet: SatochipCommandSet) {
        Log.d(TAG, "initialize START")
        CardState.cmdSet = cmdSet
        parser = cmdSet.parser
        Log.d(TAG, "initialize action: $actionType")
        Log.d(TAG, "initialize index: $actionIndex")
        resultCodeLive.postValue(NfcResultCode.Busy)

        onConnection()
    }

    fun scanCardForAction(activity: Activity) {
        Log.d(TAG, "scanCardForAction thread START")
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
        Log.d(TAG, "scanCardForAction thread END")
    }

    fun disableScanForAction() {
        Log.d(TAG, "disableScanForAction Start")
        if (activity != null) {
            if (activity?.isFinishing() == true) {
                Log.e(TAG, "NFCCardService disableScanForAction activity isFinishing()")
                return;
            }
            val nfcAdapter = NfcAdapter.getDefaultAdapter(activity)
            nfcAdapter?.disableReaderMode(activity)
            Log.d(TAG, "disableScanForAction disableReaderMode!")
        }
    }

    fun <T> checkEqual(lhs: T, rhs: T, tag: String) where T : Any, T : Comparable<T> {
        if (lhs != rhs) {
            val msg = "CheckEqual failed: got $lhs but expected $rhs in $tag"
            Log.d("testSatochip", "$msg, $tag")
            throw Exception("test error: [$tag] $msg")
        } else {
            Log.d("testSatochip", "CheckEqual ok for: $lhs")
        }
    }

    fun checkByteArrayEqual(lhs: ByteArray, rhs: ByteArray, tag: String) {
        if (!lhs.contentEquals(rhs)) {
            val msg =
                "CheckEqual failed: got ${lhs.toHexString()} but expected ${rhs.toHexString()} in $tag"
            Log.d("testSatochip", "$msg, $tag")
            throw Exception("test error: [$tag] $msg")
        } else {
            Log.d("testSatochip", "CheckEqual ok for: ${lhs.toHexString()}")
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
        Log.d("Start card reading", "CardState.onConnection")
        parser = cmdSet.parser

        try {
            val respdu: APDUResponse = cmdSet.cardSelect("seedkeeper").checkOK()
            val rapduStatus = cmdSet.cardGetStatus()//To update status if it's not the first reading

            cardStatus = cmdSet.applicationStatus ?: return
            cardStatus = ApplicationStatus(rapduStatus)

            Log.d("testSatochip", "card status: $cardStatus")

            testSeedkeeper()

            // check if setupDone
            if (cardStatus.isSetupDone == false) {
                // check version: v0.1-0.1 cannot proceed further without setup first
                println("DEBUG CardVersionInt: ${getCardVersionInt(cardStatus!!)}")
                if (getCardVersionInt(cardStatus!!) <= 0x00010001) {
                    Log.d(TAG, "Satodime v0.1-0.1 requires user to claim ownership to continue!")
                    return
                }
            }

            // check Card authenticity
            try {
                var authResults = cmdSet.cardVerifyAuthenticity()
                if (authResults != null) {
                    if (authResults[0].compareTo("OK") == 0) {
                        authenticityStatus.postValue(AuthenticityStatus.Authentic)
                    } else {
                        authenticityStatus.postValue(AuthenticityStatus.NotAuthentic)
                        Log.d(TAG, "readCard failed to authenticate card!")     // issue here.
                    }
                    certificateList.postValue(authResults.toMutableList())
                }
            } catch (e: Exception) {
                Log.d(TAG, "Failed to authenticate card with error: $e")
            }

            // get authentikey
            val respApdu = cmdSet.cardGetAuthentikey()
            // todo: get authentikey
            Log.d(TAG, "authentikeyHex: $authentikeyHex")
            isCardDataAvailable = true

            Log.d("Card read successfully", "CardState.onConnection")
        } catch (error: Exception) {
            Log.d(TAG, "An error occurred: ${error.localizedMessage}")
            Log.d(TAG, "An error occurred: $error")
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    @Throws(Exception::class)
    fun testSeedkeeper() {
        Log.d("testSatochip", "Start Seedkeeper tests")
        val cardStatus = cmdSet.applicationStatus ?: return
        val pinString = "123456"
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
                Log.d("testSatochip", "Start Seedkeeper tests: Error: $error")
            }
        }
        // verify PIN
        cmdSet.setPin0(pinBytes)
        cmdSet.cardVerifyPIN()
        // from android 8 and above
        val startTime = Instant.now()

        //Test
        testSeedkeeperMemory()
        testGenerateMasterseed()
        testGenerateRandomSecret()
        testImportExportSecretPlain()
        testImportExportSecretEncrypted()
        testBip39MnemonicV2()
        testCardBip32GetExtendedkeySeedVector1()
        testCardBip32GetExtendedkeySeedVector2()
        testCardBip32GetExtendedkeySeedVector3()
//        testCardBip32GetExtendedkeyBip85()
        resetSecrets()


        // from android 8 and above
        val endTime = Instant.now()
        // Info after tests finished
        Log.d(TAG, "tests finished, total : $nbTestTotal, success: $nbTestSuccess")
        Log.d(TAG, "time tests began: $startTime, time tests finished: $endTime")
        nbTestSuccess = 0
        nbTestTotal = 0


    }

    @Throws(Exception::class)
    fun testGenerateMasterseed() {
        Log.d(TAG, "start testGenerateMasterseed")
        nbTestTotal++
        for (seedSize in 16..64 step 16) {
            Log.d(TAG, "seedSize: $seedSize")

            val exportRights = SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED
            val label = "Test masterseed $seedSize export-allowed"
            val seedkeeperMasterSeedResult = cmdSet.seedkeeperGenerateMasterseed(
                seedSize,
                exportRights,
                label
            ) ?: continue
            checkEqual(
                seedkeeperMasterSeedResult.apduResponse.sw,
                StatusWord.OK.value,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )

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
                seedkeeperMasterSeedResult.headers[0].sid,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(lastLog.sid2, 0xFFFF, tag = "testGenerateMasterseed")
            checkEqual(lastLog.sw, StatusWord.OK.value, tag = "testGenerateMasterseed")

            // export secret and check fingerprint
            val secretObject =
                cmdSet.seedkeeperExportSecret(seedkeeperMasterSeedResult.headers[0].sid, null)
                    ?: continue
            val exportedHeader = secretObject.secretHeader
            checkEqual(
                exportedHeader.sid,
                seedkeeperMasterSeedResult.headers[0].sid,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.type,
                seedkeeperMasterSeedResult.headers[0].type,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.origin,
                seedkeeperMasterSeedResult.headers[0].origin,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.exportRights,
                seedkeeperMasterSeedResult.headers[0].exportRights,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                exportedHeader.fingerprintBytes,
                seedkeeperMasterSeedResult.headers[0].fingerprintBytes,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
//            checkEqual(exportedHeader.rfu2, header.rfu2, tag = "testGenerateMasterseed")
            checkEqual(
                exportedHeader.subtype,
                seedkeeperMasterSeedResult.headers[0].subtype,
                tag = "Function: testGenerateMasterseed, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkEqual(
                exportedHeader.label,
                seedkeeperMasterSeedResult.headers[0].label,
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
                val rapdu = cmdSet.seedkeeperResetSecret(seedkeeperMasterSeedResult.headers[0].sid)
                    ?: continue
                checkEqual(rapdu.sw, StatusWord.OK.value, tag = "testGenerateMasterseed")
            } else {
                Log.d(
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
            Log.d(
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
            val seedkeeperMasterSeedResult = cmdSet.seedkeeperGenerateRandomSecret(
                stype,
                subtype,
                size.toByte(),
                saveEntropy,
                entropy,
                exportRights,
                label
            ) ?: continue
            checkEqual(
                seedkeeperMasterSeedResult.apduResponse.sw,
                StatusWord.OK.value,
                tag = "Function: testGenerateRandomSecret, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // export master password in plaintext
            val secretHeader = seedkeeperMasterSeedResult.headers[0]
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
        Log.d(TAG, "start testImportExportSecretPlain")
        nbTestTotal++

        val bip39_12 = generateMnemonic(128)
        val bip39_18 = generateMnemonic(192)
        val bip39_24 = generateMnemonic(256)
        val bip39s = listOf(bip39_12, bip39_18, bip39_24)

        for (index in bip39s.indices) {
            val bip39String = bip39s[index]
            Log.d(TAG, "first item: $bip39String")

            val secretBytes: ByteArray =
                byteArrayOf(bip39String.toByteArray().size.toByte()) + bip39String.toByteArray()
            Log.d(TAG, "first secretBytes: ${secretBytes.size}")

            val secretFingerprintBytes = SeedkeeperSecretHeader.getFingerprintBytes(secretBytes)

            Log.d(TAG, "first secretFingerprintBytes: $secretFingerprintBytes")

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
            Log.d(TAG, "first header: $secretFingerprintBytes")

            val secretObject =
                SeedkeeperSecretObject(secretBytes, secretHeader, false, null)
            Log.d(
                TAG,
                "first secretObject: $secretObject, ${secretObject.secretHeader.fingerprintBytes.size}"
            )

            val seedkeeperImportSecretResult: SeedkeeperImportSecretResult =
                cmdSet.seedkeeperImportSecret(secretObject)
            Log.d(TAG, "first seedkeeperImportSecretResult: $seedkeeperImportSecretResult")

            checkEqual(
                seedkeeperImportSecretResult.apduResponse.sw,
                StatusWord.OK.value,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                seedkeeperImportSecretResult.fingerprintFromSeedkeeper,
                secretFingerprintBytes,
                "Function: testImportExportSecretPlain, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // export secret
            val exportedSecretObject =
                cmdSet.seedkeeperExportSecret(seedkeeperImportSecretResult.sid, null)
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
                Log.d(
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
        Log.d(TAG, "start testSeedkeeperMemory")
        nbTestTotal++

        // introduced in Seedkeeper v0.2
        if (cardStatus.protocolVersion < 0x0002) {
            Log.d(
                TAG,
                "testSeedkeeperMemory: Seedkeeper v${cardStatus.protocolVersion}: delete secret not supported!!"
            )
        }

        val sids = mutableListOf<Int>()
        val secrets = mutableListOf<SeedkeeperSecretObject>()
        val fingerprints = mutableListOf<String>()

        var secretSize = 1
        while (true) {
            println("secretSize: $secretSize")
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
                val seedkeeperImportSecretResult: SeedkeeperImportSecretResult =
                    cmdSet.seedkeeperImportSecret(
                        secretObject
                    )
                checkEqual(
                    seedkeeperImportSecretResult.apduResponse.sw,
                    StatusWord.OK.value,
                    tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkByteArrayEqual(
                    seedkeeperImportSecretResult.fingerprintFromSeedkeeper,
                    secretFingerprintBytes,
                    tag = "Function: testSeedkeeperMemory, line: ${Exception().stackTrace[0].lineNumber}"
                )
                sids.add(seedkeeperImportSecretResult.sid)
                secrets.add(secretObject)
                fingerprints.add(seedkeeperImportSecretResult.fingerprintFromSeedkeeper.toString())
            } catch (error: Exception) {
                println("[CardState.testSeedkeeperMemory] error during secret import: $error")
                break
            }

            // status todo: new class to hold these values?
            val rapdu = cmdSet.seedkeeperGetStatus()

            println("seedkeeperStatus is successful call: ${rapdu.sw}")
            secretSize += 1
        }

        // erase secrets from memory
        for (index in sids.indices) {
            println("delete object: ${index + 1} out of ${sids.size}")
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
        val rapdu = cmdSet.seedkeeperGetStatus()
        println("Finish: seedkeeperStatus is successful: ${rapdu.sw}")
        nbTestSuccess++
    }

    fun resetSecrets() {
        nbTestTotal++
        Log.d(TAG, "Start resetSecrets")
        val headers: List<SeedkeeperSecretHeader> = cmdSet.seedkeeperListSecretHeaders()
        for (header in headers) {
            Log.d(TAG, "resetSecrets Header sid: ${header.sid} comencing deletion")

            val rapdu = cmdSet.seedkeeperResetSecret(header.sid)
            checkEqual(
                rapdu.sw,
                StatusWord.OK.value,
                tag = "Function: resetSecrets, line: ${Exception().stackTrace[0].lineNumber}"
            )
            Log.d(TAG, "resetSecrets Header sid: ${header.sid} delete successful")
        }
        nbTestSuccess++
    }

    fun testImportExportSecretEncrypted() {
        nbTestTotal++
        Log.d(TAG, "Start testImportExportSecretEncrypted")
        try {
            // Get authentikey then import it in plaintext
            val authentikeyObject: AuthentikeyObject = cmdSet.cardGetSeedkeeperAuthentikey()
            val authentikeySecretBytes = ByteArray(authentikeyObject.authentikeyBytes.size + 1)
            authentikeySecretBytes[0] = authentikeyObject.authentikeyBytes.size.toByte()
            System.arraycopy(
                authentikeyObject.authentikeyBytes,
                0,
                authentikeySecretBytes,
                1,
                authentikeyObject.authentikeyBytes.size
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
            val seedkeeperImportSecretResult: SeedkeeperImportSecretResult =
                cmdSet.seedkeeperImportSecret(authentikeySecretObject)
            checkEqual(
                seedkeeperImportSecretResult.apduResponse.sw,
                StatusWord.OK.value,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                seedkeeperImportSecretResult.fingerprintFromSeedkeeper,
                authentikeyFingerprintBytes,
                "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
            )

            // Export the authentikey
            val exportedAuthentikeySecretObject =
                cmdSet.seedkeeperExportSecret(seedkeeperImportSecretResult.sid, null)
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
                val seedkeeperMasterSeedResult: SeedkeeperMasterSeedResult =
                    cmdSet.seedkeeperGenerateMasterseed(
                        size,
                        masterseedExportRights,
                        masterseedLabel
                    )
                checkEqual(
                    seedkeeperMasterSeedResult.apduResponse.sw,
                    StatusWord.OK.value,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
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
                    seedkeeperMasterSeedResult.headers[0].sid,
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
                            seedkeeperMasterSeedResult.headers[0].sid,
                            null
                        )
                    // force fail if it does not throw
                    checkEqual(
                        true,
                        false,
                        "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                    )
                } catch (error: Exception) {
                    println("Failed to export masterseed in plaintext with error: $error")
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
                    seedkeeperMasterSeedResult.headers[0].sid,
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
                        seedkeeperMasterSeedResult.headers[0].sid,
                        seedkeeperImportSecretResult.sid
                    )
                val exportedMasterseedHeader = exportedMasterseedObject.secretHeader
                checkEqual(
                    exportedMasterseedHeader.type,
                    seedkeeperMasterSeedResult.headers[0].type,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    exportedMasterseedHeader.subtype,
                    seedkeeperMasterSeedResult.headers[0].subtype,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    exportedMasterseedHeader.origin,
                    seedkeeperMasterSeedResult.headers[0].origin,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    exportedMasterseedHeader.exportRights,
                    seedkeeperMasterSeedResult.headers[0].exportRights,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkByteArrayEqual(
                    exportedMasterseedHeader.fingerprintBytes,
                    seedkeeperMasterSeedResult.headers[0].fingerprintBytes,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
//                checkEqual(
//                    exportedMasterseedHeader.rfu2,
//                    masterseedHeader.rfu2,
//                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
//                )
                checkEqual(
                    exportedMasterseedHeader.label,
                    seedkeeperMasterSeedResult.headers[0].label,
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
                    seedkeeperMasterSeedResult.headers[0].sid,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sid2,
                    seedkeeperImportSecretResult.sid,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkEqual(
                    lastLog.sw,
                    StatusWord.OK.value,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )

                // Reimport it encrypted then check if fingerprints match
                val seedkeeperImportSecretResult2: SeedkeeperImportSecretResult =
                    cmdSet.seedkeeperImportSecret(
                        exportedMasterseedObject
                    )
                checkEqual(
                    seedkeeperImportSecretResult2.apduResponse.sw,
                    StatusWord.OK.value,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
                checkByteArrayEqual(
                    seedkeeperImportSecretResult2.fingerprintFromSeedkeeper,
                    seedkeeperMasterSeedResult.headers[0].fingerprintBytes,
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
                    seedkeeperImportSecretResult.sid,
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
                        cmdSet.seedkeeperResetSecret(seedkeeperMasterSeedResult.headers[0].sid)
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
                    Log.d(
                        TAG,
                        "Seedkeeper v${cardStatus.protocolVersion}: Erasing secret not supported!"
                    )
                }
            }

            // Erase authentikey (if supported)
            if (cardStatus.protocolVersion >= 0x0002) {
                val rapdu = cmdSet.seedkeeperResetSecret(seedkeeperImportSecretResult.sid)
                checkEqual(
                    rapdu.sw,
                    StatusWord.OK.value,
                    "Function: testImportExportSecretEncrypted, line: ${Exception().stackTrace[0].lineNumber}"
                )
            } else {
                Log.d(
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
            Log.d(
                TAG,
                "Seedkeeper v${cardStatus.protocolVersion}:" +
                        " generate random_secret with external entropy not supported!"
            )
            return
        }
        nbTestTotal++
        Log.d(TAG, "Start testBip39MnemonicV2")
        val entropySizes = listOf(128, 192, 256)
        val passphrases = listOf("", "", "IveComeToTalkWithYouAgain")

        for (index in entropySizes.indices) {
            val entropySize = entropySizes[index]
            val entropy = ByteArray(entropySize / 8)
            java.security.SecureRandom().nextBytes(entropy)
            Log.d(TAG, "randomEntropyHex is $entropy")

            val bip39String = MnemonicCode.INSTANCE.toMnemonic(entropy).joinToString(" ")
            Log.d(TAG, "bip39String is $bip39String")

            val entropyBytes = MnemonicCode.INSTANCE.toEntropy(stringToList(bip39String))
            Log.d(TAG, "entropyBytes is $entropyBytes")

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
            val seedkeeperImportSecretResult: SeedkeeperImportSecretResult =
                cmdSet.seedkeeperImportSecret(secretObject)
            checkEqual(
                seedkeeperImportSecretResult.apduResponse.sw,
                StatusWord.OK.value,
                "Function: testBip39MnemonicV2, line: ${Exception().stackTrace[0].lineNumber}"
            )
            checkByteArrayEqual(
                seedkeeperImportSecretResult.fingerprintFromSeedkeeper,
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
                Log.d(
                    TAG,
                    "Seedkeeper v${cardStatus.protocolVersion}: Erasing secret not supported!"
                )
            }
        }
        nbTestSuccess++
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun testCardBip32GetExtendedkeySeedVector1() {
        nbTestTotal++
        Log.d(TAG, "Start testCardBip32GetExtendedkeySeedVector1")

        // introduced in Seedkeeper v0.2
        if (cardStatus.protocolVersion < 0x0002) {
            Log.d(TAG, "testCardBip32GetExtendedkeySeedVector1: BIP32 derivation not supported!")
        }

        // create a secret
        val masterseedHex = "000102030405060708090a0b0c0d0e0f"
        val masterseedBytes = masterseedHex.hexToByteArray()
        val secretBytes = byteArrayOf(masterseedBytes.size.toByte()) + masterseedBytes

        val secretFingerprintBytes = SeedkeeperSecretHeader.getFingerprintBytes(secretBytes)
        val label = "Test Masterseed BIP32 vector1"

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
        val seedkeeperImportSecretResult: SeedkeeperImportSecretResult =
            cmdSet.seedkeeperImportSecret(secretObject)
        checkEqual(
            seedkeeperImportSecretResult.apduResponse.sw,
            StatusWord.OK.value,
            "Function: testCardBip32GetExtendedkeySeedVector1, line: ${Exception().stackTrace[0].lineNumber}"
        )
        checkByteArrayEqual(
            seedkeeperImportSecretResult.fingerprintFromSeedkeeper,
            secretFingerprintBytes,
            "Function: testCardBip32GetExtendedkeySeedVector1, line: ${Exception().stackTrace[0].lineNumber}"
        )

        val paths = arrayOf(
            "m",
            "m/0'",
            "m/0'/1",
            "m/0'/1/2'",
            "m/0'/1/2'/2",
            "m/0'/1/2'/2/1000000000"
        )
        val xpubs = arrayOf(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        )
        // test xpub
        for (i in paths.indices) {
            println("Xpub Derivation $i")
            val path = paths[i]
            val xpub = cmdSet.cardBip32GetXpub(path, 0x0488b21e, seedkeeperImportSecretResult.sid)
            checkEqual(
                xpub,
                xpubs[i],
                "Function: testCardBip32GetExtendedkeySeedVector1, line: ${Exception().stackTrace[0].lineNumber}"
            )
        }
        // delete seed
        val respdu = cmdSet.seedkeeperResetSecret(seedkeeperImportSecretResult.sid)
        checkEqual(
            respdu.sw,
            StatusWord.OK.value,
            "Function: testCardBip32GetExtendedkeySeedVector1, line: ${Exception().stackTrace[0].lineNumber}"
        )
        nbTestSuccess++
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun testCardBip32GetExtendedkeySeedVector2() {
        nbTestTotal++
        Log.d(TAG, "Start testCardBip32GetExtendedkeySeedVector2")

        // introduced in Seedkeeper v0.2
        if (cardStatus.protocolVersion < 0x0002) {
            Log.d(TAG, "testCardBip32GetExtendedkeySeedVector2: BIP32 derivation not supported!")
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
        val seedkeeperImportSecretResult: SeedkeeperImportSecretResult =
            cmdSet.seedkeeperImportSecret(secretObject)
        checkEqual(
            seedkeeperImportSecretResult.apduResponse.sw,
            StatusWord.OK.value,
            "Function: testCardBip32GetExtendedkeySeedVector2, line: ${Exception().stackTrace[0].lineNumber}"
        )
        checkByteArrayEqual(
            seedkeeperImportSecretResult.fingerprintFromSeedkeeper,
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
            println("Xpub Derivation $i")
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
        Log.d(TAG, "Start testCardBip32GetExtendedkeySeedVector3")

        // introduced in Seedkeeper v0.2
        if (cardStatus.protocolVersion < 0x0002) {
            Log.d(TAG, "testCardBip32GetExtendedkeySeedVector3: BIP32 derivation not supported!")
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
        val seedkeeperImportSecretResult: SeedkeeperImportSecretResult =
            cmdSet.seedkeeperImportSecret(secretObject)
        checkEqual(
            seedkeeperImportSecretResult.apduResponse.sw,
            StatusWord.OK.value,
            "Function: testCardBip32GetExtendedkeySeedVector3, line: ${Exception().stackTrace[0].lineNumber}"
        )
        checkByteArrayEqual(
            seedkeeperImportSecretResult.fingerprintFromSeedkeeper,
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
            println("Xpub Derivation $i")
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
        Log.d(TAG, "Start testCardBip32GetExtendedkeyBip85")

        // introduced in Seedkeeper v0.2
        if (cardStatus.protocolVersion < 0x0002) {
            Log.d(TAG, "testCardBip32GetExtendedkeyBip85: BIP32 derivation not supported!")
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
        Log.d(TAG, "testCardBip32GetExtendedkeyBip85: entropyHex: ${entropyBytes.toHexString()}")
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
        val seedkeeperImportSecretResult: SeedkeeperImportSecretResult = cmdSet.seedkeeperImportSecret(secretObject)
        checkEqual(seedkeeperImportSecretResult.apduResponse.sw, StatusWord.OK.value, "Function: testCardBip32GetExtendedkeyBip85")
        checkByteArrayEqual(
            seedkeeperImportSecretResult.fingerprintFromSeedkeeper,
            secretFingerprintBytes,
            "Function: testCardBip32GetExtendedkeyBip85"
        )

        // export secret
        val exportedSecretObject = cmdSet.seedkeeperExportSecret(seedkeeperImportSecretResult.sid, null)
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
        Log.d(TAG, "testCardBip32GetExtendedkeyBip85: bip85EntropyBytes:  ${cmdSet.extendedKey.toHexString()}")

        val bip85EntropyBytes = cmdSet.extendedKey.copyOfRange(0,16)
        Log.d(TAG, "testCardBip32GetExtendedkeyBip85: bip85EntropyBytes: ${bip85EntropyBytes.toHexString()}")

        val bip39FromBip85 = MnemonicCode.INSTANCE.toMnemonic(bip85EntropyBytes)
        Log.d(TAG, "testCardBip32GetExtendedkeyBip85: bip39Frombip85: $bip39FromBip85")
        checkEqual(bip39FromBip85.joinToString(separator = " "), bip39bip85, "Function: testCardBip32GetExtendedkeyBip85")

        // delete masterseed
        val rapdu = cmdSet.seedkeeperResetSecret(seedkeeperImportSecretResult.sid)
        checkEqual(rapdu.sw, StatusWord.OK.value, "Function: testCardBip32GetExtendedkeyBip85")
        nbTestSuccess++
    }
}