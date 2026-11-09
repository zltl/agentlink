package app.agentlink.account

import android.content.Context
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ApplicationProvider
import app.agentlink.bridge.ClientSession
import app.agentlink.ui.AgentTheme
import app.agentlink.ui.UserLogin
import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.Certificate
import java.security.spec.NamedParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import android.security.keystore.KeyProperties

/**
 * Device-key creation and the username/password sign-in path.
 *
 * Robolectric cannot load libagentlink_ffi.so, so Ed25519 math is the JDK
 * implementation checked against RFC 8032. The relay uses the same seed
 * format (see identity::rfc8032_seed_matches_the_published_vector). The
 * Keystore provider under test has no Ed25519 algorithm.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
@OptIn(ExperimentalCoroutinesApi::class)
class DeviceKeyLoginTest {
    @get:Rule
    val rule = createComposeRule()

    private val immediate = Dispatchers.Unconfined

    @Before
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        uninstallFakeAndroidKeyStore()
        installFakeAndroidKeyStore()
        File(context().noBackupFilesDir, "keys").deleteRecursively()
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        uninstallFakeAndroidKeyStore()
    }

    @Test
    fun keystoreProviderRejectsEd25519() {
        val error = org.junit.Assert.assertThrows(NoSuchAlgorithmException::class.java) {
            KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
        }
        val message = error.message.orEmpty()
        assertTrue(message.contains("Ed25519"))
        assertTrue(message.contains("AndroidKeyStore"))
    }

    @Test
    fun softwareEd25519MatchesRfc8032() {
        val jca = JcaSoftwareEd25519()
        val seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".hexToBytes()
        assertEquals(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            jca.publicHex(seed),
        )
        val signature = jca.sign(seed, ByteArray(0))
        assertEquals(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            signature,
        )
        assertTrue(jca.verify(jca.publicHex(seed), ByteArray(0), signature))
        assertFalse(jca.verify(jca.publicHex(seed), byteArrayOf(1), signature))
    }

    @Test
    fun createWrappedDeviceKeyOnApi33() = assertCreatesWrappedKey()

    @Test
    @Config(sdk = [28])
    fun createWrappedDeviceKeyOnApi28() = assertCreatesWrappedKey()

    @Test
    @Config(sdk = [34])
    fun createWrappedDeviceKeyOnApi34() = assertCreatesWrappedKey()

    @Test
    fun existingKeystoreEd25519KeyIsReused() {
        val jca = JcaSoftwareEd25519()
        val pair = jca.keyPair("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".hexToBytes())
        val stored = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        stored.setKeyEntry(DEVICE_KEY_ALIAS, pair.private, null, arrayOf(EdCertificate(pair.public)))

        val signer = KeystoreSigner(context(), DEVICE_KEY_ALIAS, jca)
        val publicHex = signer.publicHex()
        assertEquals(jca.publicHex(pair), publicHex)
        val message = "still-the-same-device".toByteArray()
        assertTrue(jca.verify(publicHex, message, signer.sign(message)))
        assertFalse(File(context().noBackupFilesDir, "keys/$DEVICE_KEY_ALIAS.seed").exists())
        assertTrue(stored.getKey(DEVICE_KEY_ALIAS, null) is PrivateKey)
        assertEquals(null, FakeAndroidKeyStoreState.lastSpec)
    }

    @Test
    fun signInOnApi33CreatesWrappedDeviceKey() = assertSignInCreatesWrappedKey()

    @Test
    @Config(sdk = [34])
    fun signInOnApi34CreatesWrappedDeviceKey() = assertSignInCreatesWrappedKey()

    private fun assertCreatesWrappedKey() {
        val jca = JcaSoftwareEd25519()
        val signer = KeystoreSigner(context(), DEVICE_KEY_ALIAS, jca)
        val publicHex = signer.publicHex()
        assertEquals(64, publicHex.length)
        assertTrue(publicHex.matches(Regex("[0-9a-f]{64}")))
        assertEquals(publicHex, signer.publicHex())

        val message = "agentlink-login".toByteArray()
        val signature = signer.sign(message)
        assertEquals(128, signature.length)
        assertEquals(signature, signer.sign(message))
        assertTrue(jca.verify(publicHex, message, signature))
        assertFalse(jca.verify(publicHex, "other".toByteArray(), signature))

        val restarted = KeystoreSigner(context(), DEVICE_KEY_ALIAS, jca)
        assertEquals(publicHex, restarted.publicHex())
        assertTrue(jca.verify(publicHex, message, restarted.sign(message)))

        val spec = FakeAndroidKeyStoreState.lastSpec
        assertNotNull(spec)
        assertEquals(DEVICE_KEY_ALIAS, spec!!.keystoreAlias)
        assertEquals(256, spec.keySize)
        assertFalse(spec.isStrongBoxBacked)
        assertFalse(spec.isUserAuthenticationRequired)
        assertTrue(spec.isRandomizedEncryptionRequired)
        assertTrue(spec.purposes and KeyProperties.PURPOSE_ENCRYPT != 0)
        assertTrue(spec.purposes and KeyProperties.PURPOSE_DECRYPT != 0)
        assertTrue(spec.blockModes.orEmpty().contains(KeyProperties.BLOCK_MODE_GCM))
        assertTrue(spec.encryptionPaddings.orEmpty().contains(KeyProperties.ENCRYPTION_PADDING_NONE))

        val stored = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(DEVICE_KEY_ALIAS, null)
        assertTrue(stored is SecretKey)
        assertEquals("AES", stored.algorithm)

        val file = File(context().noBackupFilesDir, "keys/$DEVICE_KEY_ALIAS.seed")
        assertTrue(file.exists())
        val blob = file.readBytes()
        val seed = decryptWrappedSeed(stored as SecretKey, blob)
        assertEquals(32, seed.size)
        assertEquals(publicHex, jca.publicHex(seed))
        assertFalse(blob.containsSlice(seed))

        val other = KeystoreSigner(context(), "other.device", jca)
        assertNotEquals(publicHex, other.publicHex())

        val error = org.junit.Assert.assertThrows(NoSuchAlgorithmException::class.java) {
            KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
        }
        assertTrue(error.message.orEmpty().contains("AndroidKeyStore"))
    }

    private fun assertSignInCreatesWrappedKey() {
        val jca = JcaSoftwareEd25519()
        val sessions = MemorySession()
        val api = DeviceKeyAccount(context(), jca)
        rule.setContent {
            AgentTheme {
                UserLogin(
                    api,
                    sessions,
                    onConnected = {},
                    onActAsNode = {},
                    onAdmin = {},
                    background = immediate,
                    ui = immediate,
                )
            }
        }
        rule.onNodeWithTag("username").performTextInput("alice")
        rule.onNodeWithTag("password").performTextInput("password-alice")
        rule.onNodeWithTag("login").activate()

        val account = sessions.load()
        assertNotNull(account)
        assertEquals("alice", account!!.user)
        assertEquals(64, account.deviceId.length)
        assertEquals(1, api.loginCalls)
        assertTrue(jca.verify(account.deviceId, api.signedMessage, api.signature))
        rule.onNodeWithTag("session-user").assertTextEquals("alice")
        assertEquals(
            0,
            rule.onAllNodesWithText("NoSuchAlgorithmException", substring = true).fetchSemanticsNodes().size,
        )
        assertEquals(
            0,
            rule.onAllNodesWithText("AndroidKeyStore", substring = true).fetchSemanticsNodes().size,
        )

        val stored = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(DEVICE_KEY_ALIAS, null)
        assertEquals("AES", stored.algorithm)
        val spec = FakeAndroidKeyStoreState.lastSpec
        assertNotNull(spec)
        assertEquals(DEVICE_KEY_ALIAS, spec!!.keystoreAlias)
        assertFalse(spec.isStrongBoxBacked)

        val again = KeystoreSigner(context(), DEVICE_KEY_ALIAS, jca)
        assertEquals(account.deviceId, again.publicHex())
        assertTrue(jca.verify(account.deviceId, api.signedMessage, again.sign(api.signedMessage)))
    }
}

private fun context(): Context = ApplicationProvider.getApplicationContext()

private class MemorySession : SessionStore {
    private var account: UserAccount? = null
    override fun load(): UserAccount? = account
    override fun save(account: UserAccount) { this.account = account }
    override fun clear() { account = null }
}

/**
 * Same calls login makes: read the device public key, then sign the challenge.
 * A Keystore Ed25519 failure surfaces as the red sign-in error.
 */
private class DeviceKeyAccount(
    context: Context,
    software: SoftwareEd25519,
) : AccountApi {
    private val signer = KeystoreSigner(context, DEVICE_KEY_ALIAS, software)
    var loginCalls = 0
    lateinit var signedMessage: ByteArray
    lateinit var signature: String

    override fun login(
        server: String,
        fingerprint: String,
        username: String,
        password: String,
        totp: String,
        deviceName: String,
    ): UserAccount {
        loginCalls += 1
        val publicHex = signer.publicHex()
        signedMessage = "agentlink-login-v1:$username".toByteArray()
        signature = signer.sign(signedMessage)
        return UserAccount(server, fingerprint, username, "user", publicHex, "atk.test", 0, "rtk.test")
    }

    override fun refresh(account: UserAccount): UserAccount = account
    override fun logout(account: UserAccount) = Unit
    override fun listNodes(account: UserAccount): List<NodeRow> = emptyList()
    override fun listDevices(account: UserAccount): List<DeviceRow> = emptyList()
    override fun enrollAsNode(account: UserAccount, name: String) = Unit
    override fun connect(account: UserAccount): ClientSession {
        throw UnsupportedOperationException("connect")
    }
}

internal class JcaSoftwareEd25519 : SoftwareEd25519 {
    override fun publicHex(seed: ByteArray): String = publicHex(keyPair(seed))

    override fun sign(seed: ByteArray, message: ByteArray): String {
        val signature = Signature.getInstance("Ed25519")
        signature.initSign(keyPair(seed).private)
        signature.update(message)
        return signature.sign().toHex()
    }

    fun publicHex(pair: KeyPair): String {
        val encoded = pair.public.encoded
        return encoded.copyOfRange(encoded.size - 32, encoded.size).toHex()
    }

    fun keyPair(seed: ByteArray): KeyPair {
        val generator = KeyPairGenerator.getInstance("Ed25519")
        generator.initialize(NamedParameterSpec.ED25519, SeededRandom(seed))
        return generator.generateKeyPair()
    }

    fun verify(publicHex: String, message: ByteArray, signatureHex: String): Boolean {
        val raw = publicHex.hexToBytes()
        val prefix = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        )
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(prefix + raw))
        val signature = Signature.getInstance("Ed25519")
        signature.initVerify(key)
        signature.update(message)
        return signature.verify(signatureHex.hexToBytes())
    }
}

private class SeededRandom(private val seed: ByteArray) : SecureRandom() {
    override fun nextBytes(bytes: ByteArray) {
        check(bytes.size == seed.size) { "Ed25519 keygen asked for ${bytes.size} bytes" }
        System.arraycopy(seed, 0, bytes, 0, seed.size)
    }
}

private class EdCertificate(private val key: PublicKey) : Certificate("Ed25519") {
    override fun getEncoded(): ByteArray = key.encoded
    override fun getPublicKey(): PublicKey = key
    override fun verify(publicKey: PublicKey) = Unit
    override fun verify(publicKey: PublicKey, sigProvider: String) = Unit
    override fun toString(): String = "Ed25519"
}

private fun decryptWrappedSeed(key: SecretKey, blob: ByteArray): ByteArray {
    val ivLen = blob[0].toInt() and 0xff
    val iv = blob.copyOfRange(1, 1 + ivLen)
    val body = blob.copyOfRange(1 + ivLen, blob.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
    return cipher.doFinal(body)
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0)
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

private fun ByteArray.containsSlice(needle: ByteArray): Boolean {
    if (needle.isEmpty() || size < needle.size) return false
    for (start in 0..size - needle.size) {
        var same = true
        for (index in needle.indices) {
            if (this[start + index] != needle[index]) {
                same = false
                break
            }
        }
        if (same) return true
    }
    return false
}

private fun SemanticsNodeInteraction.activate() = performSemanticsAction(SemanticsActions.OnClick)
