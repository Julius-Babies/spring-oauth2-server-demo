package es.jvbabi.springoauth2serverdemo.configuration

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder

@Configuration
class JwtConfiguration {

    @Autowired lateinit var userDetailsService: UserDetailsService
    @Autowired lateinit var passwordEncoder: PasswordEncoder

    @Bean
    fun authenticationProvider(): AuthenticationProvider {
        val provider = DaoAuthenticationProvider()
        provider.setUserDetailsService(userDetailsService)
        provider.setPasswordEncoder(passwordEncoder)
        return provider
    }

    @Bean
    fun jwtDecoder(rsaKeyProperties: RsaKeyProperties): JwtDecoder {
        return NimbusJwtDecoder.withPublicKey(rsaKeyProperties.publicKey).build()
    }

    @Bean
    fun jwtEncoder(rsaKeyProperties: RsaKeyProperties): JwtEncoder {
        val jwk =
            com.nimbusds.jose.jwk.RSAKey.Builder(rsaKeyProperties.publicKey).privateKey(rsaKeyProperties.privateKey)
                .build()
        val source = ImmutableJWKSet<SecurityContext>(JWKSet(jwk))
        return NimbusJwtEncoder(source)
    }
}