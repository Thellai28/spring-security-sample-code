package com.thellai.springsecurity.basicSecurity;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration // Going to use jwt for security, so disabling it :
@EnableWebSecurity // this is not mandatory, this annotation lets spring konw that this class is part of spring security
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true) // what is method security, what is the difference between global and method security ?
public class BasicAuthSecurityConfiguration {

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

        http.headers().frameOptions().sameOrigin(); // by default, the spring will block all the frames, H2 console uses
        // frames to display in content in web browser, so we are allowing frames from same URL or same

        return http.build();

        //http.formLogin(withDefaults());

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

//    @Bean
//    public UserDetailsService userDetailsService() {
//        var user = User.withUsername("Thellai")
//                .password("{noop}password")
//                .roles(String.valueOf(UserRoles.USER)).build();
//       /*
//            The password for the user "Thellai" is set to "password," and the {noop}
//            prefix tells Spring Security not to perform any additional encoding on this
//            password. This is commonly used during development or for scenarios where you
//            intentionally want to use plain text passwords, but it's generally not
//            recommended for production systems.
//       */
//
//        var admin = User.withUsername("admin") // Not TWo users can have same user name :
//                .password("{noop}password")
//                .roles(String.valueOf(UserRoles.ADMIN)).build();
//
//
//        return  new InMemoryUserDetailsManager( user, admin );
//    }

    @Bean
    public DataSource dataSource(){ // This will create the basic schema of data base :
        return  new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService( DataSource dataSource) { // TO store user details :
        var user = User.withUsername("thellai")
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
}
