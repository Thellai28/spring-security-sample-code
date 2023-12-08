package com.thellai.springsecurity.resources;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
@RestController
public class TodoResources {
    private Logger logger = LoggerFactory.getLogger( getClass() );

    public static final List<Todo> todos = List.of(
            new Todo("thellai", "i wanna become best software developer in the world"),
            new Todo("Dhinesh", "i wanna become best software developer in the world"),
            new Todo("tthella", "i wanna become best software developer in the world"),
            new Todo("ThellaiVananDhinesh", "i wanna become best software developer in the world"),
            new Todo("admin", "i wanna become best software developer in the world")
    );

    @GetMapping( "/todos")
    public List<Todo> retrieveAllTodos(){

        return todos;
    }

    @GetMapping( "/users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    //@PreAuthorize("hasRole('ADMIN') and #username == authentication.name")
    @PostAuthorize("returnObject.username == 'thellai' ")
    @RolesAllowed( {"ADMIN","USER" } ) // From jsr 250 : person with user roles ADMIN & USER can only access  the method
    @Secured( {"ROLE_ADMIN", "ROLE_USER"})
    public Todo retrieveTodosForSpecificUser( @PathVariable String username ){

        return todos.get(0);

        /* @PreAuthorize :

            In Spring Security's method security expressions, the # symbol is used to reference method parameters.
            When you see #username in the @PreAuthorize annotation, it means that the expression is referring to the
            username parameter of the method.

            @PostAuthorize :

            In the @PostAuthorize annotation, the expression is evaluated after the method has been invoked but
            before the result is returned to the caller. It's typically used to perform additional authorization checks
            based on the result of the method.
        */
    }

    @PostMapping( "/users/{username}/todos")
    public void createTodoForSpecifcUser( @PathVariable String username, @RequestBody Todo todo  ){

        logger.info("Creating {} for {}", todo, username);
    }
}

record Todo(String username, String description ){}
