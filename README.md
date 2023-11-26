# Tutorial de Spring Security - JWT - Roles de usuario - CORS

En este tutorial aprenderás:
- Implementación de **Spring Security**
- Login y Registro con **Json Web Token**
- Autorizar el acceso a un endpoint a usuarios con un **rol** determinado
- Configuración de **CORS** para que el Front-end pueda acceder a tu proyecto

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

En esta clase están los endpoints para autenticación. Estos métodos no estarán protegidos. Ambos devolverán un JWT. <br>
Llama a los métodos de la Clase Servicio Authservice.
  

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


## 3 - Crear Clases DTO
Creamos las clases **LoginDto** y **RegistroDto** que recibirán como parámetro los endpoints de Login y Registro.
También **AuthResponse**, que es la respuesta que retornarán esos endpoints con el JWT.

```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegistroDto {
    String email;
    String password;
    String nombre;
    String apellido;
    String pais; 
    String rol;
}
```


```java
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginDto {
    String email;
    String password; 
}
```

```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    String token; 
}
```

## 4 - Implementar UserDetails en tu Entidad Usuario
- UserDetails es un usuario de Spring Security. Debes implementarla en la entidad que será el usuario de tu app (User, Usuario, Persona, etc.).
- UserDetails tiene como atributos **username** y **password**. Aquí sobreescribimos el método getUsername y le indicamos que usaremos el email como username.
- En este caso no hizo falta sobreescribir el método getPassword porque ya tenemos un atributo password en la entidad User, y Lombok se está encargando de crear el getter por la anotación @Data. Si al campo le pusiste otro nombre (ej: contrasena) tu IDE te forzará a implementar el método getPassword, al cual habrá que pasarle el atributo contrasena.
- Le agregamos como atributo el Rol. **Los roles estarán listados en una Clase Enumerador**.
- En el método getAuthorities le pasamos el rol, serán los permisos que tiene ese usuario.
- A los métodos de expiración le ponemos todo true. No los usaremos, ya que eso se manejará con el JWT.


```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Integer id;
    String email;
    String apellido;
    String nombre;
    String pais;
    String password;
    
    @Enumerated(EnumType.STRING) 
    Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      return List.of(new SimpleGrantedAuthority((role.name())));
    }
    @Override
    public String getUsername() {
        return email;
    } 
    @Override
    public boolean isAccountNonExpired() {
       return true;
    }
    @Override
    public boolean isAccountNonLocked() {
       return true;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

```java
public enum Role {
	COMPRADOR,
    VENDEDOR  
}
```

## 5 - Agregar query en Clase Repositorio
En el repositorio de tu clase usuario agregamos un método para buscar por el atributo que habíamos decidido utilizar como username, en este caso el email.

```java
public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findByEmail(String email); 
}
```


## 6 - Crear Clase de Configuración SecurityConfig

- Esta clase contiene la **SecurityFilterChain**. Todas las requests que reciba nuestra API pasarán por esta cadena de filtros.<br>
- Le indicamos que los endpoints en la ruta /auth/ (login y registro) serán públicos. <br>
- Para acceder a los demás endpoints, el usuario deberá estar autenticado (   .anyRequest().authenticated() )<br>
- Deshabilitamos csrf y session. Son métodos predeterminados de Spring Security que no usaremos, porque la autenticación la haremos con JWT.
- Agregamos el **jwtAuthenticationFilter** (lo desarrollaremos luego).<br>
- El authenticationProvider es el responsable de recibir una solicitud de autorización y decidir si es válida o no. Más adelante, en otra clase de configuración indicaremos cuál provider implementaremos.<br>
- La anotación @EnableMethodSecurity(securedEnabled = true) nos permitirá incluir en los controladores la anotación **@Secured** para indicar el rol de los usuarios que tendrán acceso a los mismos.<br>


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




## 7 - Crear Filtro JwtAuthenticationFilter
Ya indicamos anteriormente en SecurityConfig que todas las peticiones deben pasar por este filtro.
- El filtro hereda de OncePerRequestFilter (se ejecutará una vez sola por cada request).
- Obtenemos el token que viene incluido en la request llamando al método getTokenFromRequest (ver más abajo). El mismo busca el token que está en el HEADER de la request y le quita la palabra "Bearer".
- Si la request no tiene JWT, continuamos con la cadena de filtros, donde habíamos indicado que solo podría acceder al login y registro en /auth/.
- Si la request viene con un JWT, buscará el usuario en nuestra Base de Datos. Luego lo validará (credenciales correctas, no expirado) y si está todo ok lo guardará en el SecurityContextHolder.
- SecurityContextHolder es un método estático para recuperar los datos del usuario. Permitirá llamarlo desde cualquier parte de nuestro código sin pasarle ningún parámetro.



```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
       
        final String token = getTokenFromRequest(request);
        final String username;

        if (token==null)
        {
            filterChain.doFilter(request, response);
            return;
        }

        username=jwtService.getUsernameFromToken(token);

        if (username!=null && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            UserDetails userDetails=userDetailsService.loadUserByUsername(username);

            if (jwtService.isTokenValid(token, userDetails))
            {
                UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }
        
        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);

        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer "))
        {
            return authHeader.substring(7);
        }
        return null;
    } 
}
```





