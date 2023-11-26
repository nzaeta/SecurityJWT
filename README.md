# Tutorial de Spring Security - JWT - Roles de usuario - CORS

En este tutorial aprenderás:
- Implementación de Spring Security
- Login y Registro con Json Web Token
- Autorizar el acceso a un endpoint a usuarios con un rol determinado
- Configuración de CORS para que el Front-end pueda acceder a tu proyecto

<br>

Si querés ejecutar el proyecto de este repositorio:
- Crear una base de datos de nombre "securityJWT".
- Revisar en application.properties las credenciales de acceso (por defecto username: root, password: root)

<br>

## Intro Autenticación con Json Web Token

Al loguearse el usuario, si las credenciales (usuario y contraseña) son válidas, le enviará al front un JWT.<br>
El front almacenará ese JWT en una cookie o sessionStorage, y lo incluirá en las posteriores requests para acceder a los endpoints protegidos.<br>
El JWT contiene: 
- HEADER: tipo de token y algoritmo de firma utilizado
- PAYLOAD: id usuario, roles, permisos. Se le pueden agregar más datos
- SIGNATURE: para garantizar que no haya sido manipulado
<br>

## 1 - Crear Proyecto Spring / Agregar dependencias a pom.xml

Al crear el proyecto con Spring Initializr debes agregar las siguientes dependencias:
- Spring Web
- Spring Security
- Spring Data JPA
- MySQL Driver
- Lombok (librería de anotaciones para ahorrarse el código de getters, setters y constructores)
- Validation (anotaciones para validar atributos @NotNull, @NotBlank, etc.)
  
Además hay que agregar manualmente las dependencias de JWT.

```html
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-api</artifactId>
			<version>0.11.5</version>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-impl</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
```

<br>

## 2 - Crear Clase Controlador AuthController

En esta clase están los endpoints para autenticación. Estos métodos no estarán protegidos. <br>
Llama a los métodos que estarán en la Clase Servicio Authservice.
  

```java
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    
    @PostMapping("login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginDto datos) {
    	try {
    		return ResponseEntity.ok(authService.login(datos));
        } catch (RuntimeException e) {
            return new ResponseEntity(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("registro")
    public ResponseEntity<AuthResponse> registro(@RequestBody RegistroDto datos) {
    	try {
    		return ResponseEntity.ok(authService.registro(datos));
        } catch (RuntimeException e) {
            return new ResponseEntity(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

}
```

<br>

## 3 - Crear Clase de Configuración SecurityConfig

- Esta clase contiene la SecurityFilterChain. Todas las requests que reciba nuestra API pasarán por esta cadena de filtros.<br>
- Le indicamos que los endpoints en la ruta /auth/ (login y registro) serán públicos. <br>
- Para acceder a los demás endpoints, el usuario deberá estar autenticado (   .anyRequest().authenticated() )<br>
- Deshabilitamos csrf y session. Son métodos predeterminados de Spring Security que no usaremos, porque la autenticación la haremos con JWT (agregamos el jwtAuthenticationFilter, lo desarrollaremos luego).<br>
- El authenticationProvider es el responsable de recibir una solicitud de autorización y decidir si es válida o no. Más adelante, en otra clase de configuración indicaremos cuál provider implementaremos.<br>
- La anotación @EnableMethodSecurity(securedEnabled = true) nos permitirá incluir en los controladores la anotación @Secured para indicar el rol de los usuarios que tendrán acceso a los mismos.<br>


```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        return http
            .csrf(csrf -> 
                csrf
                .disable())
            .authorizeHttpRequests(authRequest ->
              authRequest
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()
                )
            .sessionManagement(sessionManager->
                sessionManager 
                  .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authProvider)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}
```
<br>








