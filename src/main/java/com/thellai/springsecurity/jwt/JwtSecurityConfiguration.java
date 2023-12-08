package com.thellai.springsecurity.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import com.nimbusds.jose.jwk.RSAKey;


import javax.sql.DataSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

//@Configuration
//@EnableWebSecurity // this is not mandatory, this annotation lets spring konw that this class is part of spring security
public class JwtSecurityConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain( HttpSecurity http) throws Exception {
         http.authorizeHttpRequests( // Should authenticate all reqeuests that comes in :
                (requests) -> requests.anyRequest().authenticated()
        ).sessionManagement( // Making our Rest API stateless :
                session -> session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS)
        ). httpBasic(
                withDefaults()
        ).csrf().disable();
         http.oauth2ResourceServer( OAuth2ResourceServerConfigurer::jwt );

        http.headers().frameOptions().sameOrigin();
        // by default, the spring will block all the frames, H2 console uses
        // frames to display in content in web browser, so we are allowing frames from same URL or same

        return http.build();

        /*
            Since we have created our rest API as state less, there will be no session token will be
            created , when ever a login in session is authenticated. Since there is not session created, no
            tokens will be  created and sent as a part of header in response for initial authentication.

            if there is no token generated and sent, how can you expect a token in header in all the subsequent
            request from this session? At this point, for stateless REST API'S, all the request after login will fail
            since there is no tokens associated in headers. To provent this, while creating our REST API'S as stateless
            we disable the CSRF filter.
         */
    }


    @Bean
    public DataSource dataSource(){ // This will create the basic schema of data base :
        return  new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }



    @Bean
    public UserDetailsService userDetailsService( DataSource dataSource) { // TO store user details :
        var user = User.withUsername("Thellai")
                .password("password")
                .passwordEncoder( strPwd -> passwordEncoder().encode(strPwd) ) // hashing the password using bcrypt :
                .roles(String.valueOf(UserRoles.USER))
                .build();
       /*
            The password for the user "Thellai" is set to "password," and the {noop}
            prefix tells Spring Security not to perform any additional encoding on this
            password. This is commonly used during development or for scenarios where you
            intentionally want to use plain text passwords, but it's generally not
            recommended for production systems.
       */

        var admin = User.withUsername("admin") // Not TWo users can have same user name :
                .password("password")
                .passwordEncoder( strPwd -> passwordEncoder().encode(strPwd) )
                .roles( String.valueOf(UserRoles.ADMIN), String.valueOf(UserRoles.USER) )
                .build();

        var jdbcUserDetailsManager = new JdbcUserDetailsManager( dataSource );
        jdbcUserDetailsManager.createUser( user );
        jdbcUserDetailsManager.createUser( admin );


        return  jdbcUserDetailsManager;
    }



    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        // To encode your passwords, Bcrypt, sCrypt & Argon2 use hasing,
        // To decode the password. When your hash a particular password, you cannot get the original value back unlike
        //  encoding and encrypting
        return new BCryptPasswordEncoder();
    }

    @Bean
    public KeyPair keyPair() { // Generating the RSA key pair :
        try{
            var keyPairGenerator = KeyPairGenerator.getInstance( "RSA" );
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        }catch ( Exception ex ){
            throw new RuntimeException(ex);
        }
        /*

            In the code snippet you provided, initialize(2048) is a method call on a KeyPairGenerator instance, and it
            specifies the key size to be used when generating an RSA key pair.

             Here's a breakdown:

             KeyPairGenerator.getInstance("RSA"): This line creates an instance of the KeyPairGenerator class,
             specifying that it will be used for generating RSA key pairs. keyPairGenerator.initialize(2048): This line
             initializes the KeyPairGenerator with a key size of 2048 bits. The key size determines the length of
             the modulus in the RSA key pair. In RSA, the security of the key pair is directly related to the key size.
             Common key sizes include 1024, 2048, and 4096 bits.
        */
    }



    @Bean
    public RSAKey rsaKey( KeyPair keyPair ){
        return new RSAKey
                .Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey( keyPair.getPrivate() )
                .keyID(UUID.randomUUID().toString())
                .build();
    }



    @Bean
    public JWKSource<SecurityContext> jwkSource( RSAKey rsaKey ){
        var jwkSet = new JWKSet(rsaKey);
//        new JWKSource(){
//            public List get( JWKSelector jwkSelector, SecurityContext context ){
//                return  jwkSelector.select( jwkSet);
//            }
//        };

       return  (jwkSelector,  context ) -> jwkSelector.select(jwkSet);
    }


    @Bean
    public JwtDecoder jwtDecoder( RSAKey rsaKey ) throws JOSEException {
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey() )
                .build();
    }





    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){
        return new NimbusJwtEncoder(jwkSource);
    }





}
