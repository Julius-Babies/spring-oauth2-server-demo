package es.jvbabi.springoauth2serverdemo

import es.jvbabi.springoauth2serverdemo.configuration.RsaKeyProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties::class)
class SpringOauth2ServerDemoApplication

fun main(args: Array<String>) {
    runApplication<SpringOauth2ServerDemoApplication>(*args)
}
