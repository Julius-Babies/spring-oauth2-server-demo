package es.jvbabi.springoauth2serverdemo.configuration

import org.springframework.boot.context.properties.ConfigurationProperties
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey


@ConfigurationProperties(prefix = "rsa")
@JvmRecord
data class RsaKeyProperties(val publicKey: RSAPublicKey, val privateKey: RSAPrivateKey)