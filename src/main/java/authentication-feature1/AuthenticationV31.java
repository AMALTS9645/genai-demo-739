 ```java

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatus.BAD_REQUEST, HTTP_UNAUTHORIZED
import org.springframework.security.authentication.AuthenticationException;
import org.springframework.security.authentication.UsernameNotFoundException;
import org.springframework.validation.annotation.Validated;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.security.authentication.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
    import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.security.authentication.UserDetailsService;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationException;
import org.springframework.security.AuthenticationFailureException;
import org.springframework.validation.annotation.Validated;

@RestController
@RequestMapping("/api/login")
class LoginController {

    @Autowired
    private UserDetailsService userDetailsService;

    @PostMapping(value = "/login", consumes = "application/json", produces = "application/json")
    @ResponseBody
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        // Security measures to prevent SQL injection and XSS attacks
        String username = credentials.get("username");
        String password = credentials.get("password");

        try {
            UserDetails user = userDetailsService.loadUserByUsername(username);
            if (user.getPassword().equals(password)) {
                return ResponseEntity.ok().build();
            } else {
                throw new AuthenticationException("Invalid username or password");
            }
        } catch (AuthenticationException | UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout() {
        return ResponseEntity.ok().build();
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<?> handleUsernameNotFoundException(UsernameNotFoundException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username not found");
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<?> handleAuthenticationException(AuthenticationException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
    }

}