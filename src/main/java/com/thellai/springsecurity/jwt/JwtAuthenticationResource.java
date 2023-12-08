package com.thellai.springsecurity.jwt;

import org.apache.logging.log4j.CloseableThreadContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;


//@RestController
public class JwtAuthenticationResource {
    private JwtEncoder jwtEncoder; // To create a JWT token, we need encoder :

    public JwtAuthenticationResource( JwtEncoder jwtEncoder ) {
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping("/authenticate")
    public JwtResponse authenticate(Authentication authentication) {
        return new JwtResponse(createToken(authentication));
    }


    private  String createToken( Authentication authentication ) {
        var claims = JwtClaimsSet.builder()
                        .issuer("self")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(60 * 3))
                        .subject( authentication.getName() )
                        .claim("scope", createScope( authentication ) )
                        .build();


//        JwtEncoderParameters parameter = JwtEncoderParameters.from(claims);
//        return jwtEncoder.encode( parameter ).getTokenValue();
        return jwtEncoder.encode(JwtEncoderParameters.from(claims))
                .getTokenValue();
    }



    private String createScope( Authentication authentication ) {
        return  authentication.getAuthorities()
                .stream()
                .map( a -> a.getAuthority() )
                .collect( Collectors.joining(" ") );

    }

}

record JwtResponse( String token ){}