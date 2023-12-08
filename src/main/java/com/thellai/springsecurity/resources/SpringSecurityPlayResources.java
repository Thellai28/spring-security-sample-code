package com.thellai.springsecurity.resources;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringSecurityPlayResources {

    @GetMapping( "/csrf-token")
    public CsrfToken retrieveCsrfToken( HttpServletRequest request ){

        return (CsrfToken) request.getAttribute("_csrf" );
    }
}
