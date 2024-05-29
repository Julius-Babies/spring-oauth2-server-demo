package es.jvbabi.springoauth2serverdemo.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
class MyController {

    @GetMapping("/secret")
    fun secret(principal: Principal): String {
        return "Hello, ${principal.name}!"
    }
}