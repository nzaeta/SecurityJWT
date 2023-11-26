package com.nzaeta.SecurityJWT.Auth;

import java.util.Optional;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.nzaeta.SecurityJWT.Dto.AuthResponse;
import com.nzaeta.SecurityJWT.Dto.LoginDto;
import com.nzaeta.SecurityJWT.Dto.RegistroDto;
import com.nzaeta.SecurityJWT.Entity.User;
import com.nzaeta.SecurityJWT.Jwt.JwtService;
import com.nzaeta.SecurityJWT.Repository.UserRepository;
import com.nzaeta.SecurityJWT.Enum.Role;


import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse login(LoginDto datos) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(datos.getEmail(), datos.getPassword()));
        UserDetails user = userRepository.findByEmail(datos.getEmail()).orElseThrow();
        String token = jwtService.getToken(user);
        return AuthResponse.builder()
            .token(token)
            .build();

    }

    public AuthResponse registro(RegistroDto datos) {
    	
        Optional<User> userOptional = userRepository.findByEmail(datos.getEmail());
        if (userOptional.isPresent()) {
            throw new RuntimeException("Ya existe un usuario con ese email");
        }
        
        User user = User.builder()
            .email(datos.getEmail())
            .password(passwordEncoder.encode(datos.getPassword()))
            .nombre(datos.getNombre())
            .apellido(datos.getApellido())
            .pais(datos.getPais())
            .role(Role.valueOf(datos.getRol()))
            .build();

        userRepository.save(user);

        return AuthResponse.builder()
            .token(jwtService.getToken(user))
            .build();
        
    }

}
