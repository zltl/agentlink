package app.agentlink.account

import android.security.keystore.KeyGenParameterSpec
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidAlgorithmParameterException
import java.security.Key
import java.security.KeyStoreException
import java.security.KeyStoreSpi
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.cert.Certificate
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.KeyGenerator
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey
import java.security.spec.AlgorithmParameterSpec

/**
 * AndroidKeyStore stand-in for Robolectric. It serves AES-GCM wrap keys and
 * rejects Ed25519, which is the failure real devices raise as
 * `NoSuchAlgorithmException: no such algorithm: Ed25519 for provider AndroidKeyStore`.
 */
internal object FakeAndroidKeyStoreState {
    val keys: MutableMap<String, Key> = ConcurrentHashMap()
    val certs: MutableMap<String, Certificate> = ConcurrentHashMap()
    var lastSpec: KeyGenParameterSpec? = null

    fun reset() {
        keys.clear()
        certs.clear()
        lastSpec = null
    }
}

internal fun installFakeAndroidKeyStore() {
    Security.getProviders()
        .filter { it.name == "AndroidKeyStore" }
        .forEach { Security.removeProvider(it.name) }
    Security.addProvider(FakeAndroidKeyStoreProvider())
}

internal fun uninstallFakeAndroidKeyStore() {
    Security.removeProvider("AndroidKeyStore")
    FakeAndroidKeyStoreState.reset()
}

class FakeAndroidKeyStoreProvider : Provider(
    "AndroidKeyStore",
    1.0,
    "AES wrap keystore that does not implement Ed25519",
) {
    init {
        putService(
            Service(
                this,
                "KeyStore",
                "AndroidKeyStore",
                FakeAndroidKeyStoreSpi::class.java.name,
                null,
                null,
            ),
        )
        putService(
            Service(
                this,
                "KeyGenerator",
                "AES",
                FakeAesKeyGeneratorSpi::class.java.name,
                null,
                null,
            ),
        )
    }
}

class FakeAndroidKeyStoreSpi : KeyStoreSpi() {
    override fun engineAliases(): Enumeration<String> = Collections.enumeration(FakeAndroidKeyStoreState.keys.keys)

    override fun engineContainsAlias(alias: String): Boolean = FakeAndroidKeyStoreState.keys.containsKey(alias)

    override fun engineDeleteEntry(alias: String) {
        FakeAndroidKeyStoreState.keys.remove(alias)
        FakeAndroidKeyStoreState.certs.remove(alias)
    }

    override fun engineGetCertificate(alias: String): Certificate? = FakeAndroidKeyStoreState.certs[alias]

    override fun engineGetCertificateAlias(cert: Certificate): String? =
        FakeAndroidKeyStoreState.certs.entries.firstOrNull { it.value == cert }?.key

    override fun engineGetCertificateChain(alias: String): Array<Certificate>? {
        val cert = FakeAndroidKeyStoreState.certs[alias] ?: return null
        return arrayOf(cert)
    }

    override fun engineGetCreationDate(alias: String): Date? =
        if (engineContainsAlias(alias)) Date(0) else null

    override fun engineGetKey(alias: String, password: CharArray?): Key? = FakeAndroidKeyStoreState.keys[alias]

    override fun engineIsCertificateEntry(alias: String): Boolean =
        FakeAndroidKeyStoreState.certs.containsKey(alias) && !FakeAndroidKeyStoreState.keys.containsKey(alias)

    override fun engineIsKeyEntry(alias: String): Boolean = FakeAndroidKeyStoreState.keys.containsKey(alias)

    override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit

    override fun engineSetCertificateEntry(alias: String, cert: Certificate) {
        FakeAndroidKeyStoreState.certs[alias] = cert
    }

    override fun engineSetKeyEntry(alias: String, key: ByteArray, chain: Array<out Certificate>?) {
        throw KeyStoreException("raw key entries are not used")
    }

    override fun engineSetKeyEntry(alias: String, key: Key, password: CharArray?, chain: Array<out Certificate>?) {
        FakeAndroidKeyStoreState.keys[alias] = key
        if (chain != null && chain.isNotEmpty()) {
            FakeAndroidKeyStoreState.certs[alias] = chain[0]
        } else {
            FakeAndroidKeyStoreState.certs.remove(alias)
        }
    }

    override fun engineSize(): Int = FakeAndroidKeyStoreState.keys.size

    override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit
}

class FakeAesKeyGeneratorSpi : KeyGeneratorSpi() {
    private var alias: String? = null

    override fun engineInit(random: SecureRandom) {
        throw InvalidAlgorithmParameterException("AndroidKeyStore AES keys need a KeyGenParameterSpec")
    }

    override fun engineInit(keysize: Int, random: SecureRandom) {
        throw InvalidAlgorithmParameterException("AndroidKeyStore AES keys need a KeyGenParameterSpec")
    }

    override fun engineInit(params: AlgorithmParameterSpec, random: SecureRandom) {
        val spec = params as? KeyGenParameterSpec
            ?: throw InvalidAlgorithmParameterException("expected KeyGenParameterSpec")
        alias = spec.keystoreAlias
        FakeAndroidKeyStoreState.lastSpec = spec
    }

    override fun engineGenerateKey(): SecretKey {
        val name = alias ?: throw IllegalStateException("KeyGenerator.init was not called")
        val providers = Security.getProviders().filter { it.name != "AndroidKeyStore" }
        val provider = providers.firstOrNull { it.getService("KeyGenerator", "AES") != null }
            ?: throw IllegalStateException("no AES KeyGenerator besides AndroidKeyStore")
        val key = KeyGenerator.getInstance("AES", provider).apply { init(256) }.generateKey()
        FakeAndroidKeyStoreState.keys[name] = key
        FakeAndroidKeyStoreState.certs.remove(name)
        return key
    }
}
