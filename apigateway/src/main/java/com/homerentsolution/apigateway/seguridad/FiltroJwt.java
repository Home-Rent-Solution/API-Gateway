package com.homerentsolution.apigateway.seguridad;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

// Filtro global: revisa el token JWT de cada petición antes de enviarla al microservicio
// y aplica las reglas de acceso por rol.
@Component
public class FiltroJwt implements GlobalFilter, Ordered {

    // rutas de documentación del Gateway (/propiedades/..., /reservas/...): Swagger las usa
    // también para "Try it out", así que se revisan igual que /api/v1/...
    private static final List<String> PREFIJOS_DOCS = List.of(
            "/comentarios", "/propiedades", "/anfitriones", "/inquilinos", "/reservas", "/pagos",
            "/limpieza", "/mensajeria", "/precios", "/seguros", "/usuarios");

    // cabeceras con los datos del token que el Gateway envía a los microservicios
    public static final String CABECERA_CORREO = "X-Usuario-Correo";
    public static final String CABECERA_ROL = "X-Usuario-Rol";

    private final SecretKey clave;

    // el mismo secreto que usa MS-Usuarios para firmar los tokens
    public FiltroJwt(@Value("${jwt.secreto}") String secreto) {
        this.clave = Keys.hmacShaKeyFor(secreto.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpMethod metodo = exchange.getRequest().getMethod();
        String ruta = rutaReal(exchange.getRequest().getURI().getPath());

        // estas cabeceras solo las pone el Gateway: si llegan desde afuera se borran,
        // así nadie puede hacerse pasar por otro usuario
        ServerWebExchange limpio = exchange.mutate()
                .request(peticion -> peticion.headers(cabeceras -> {
                    cabeceras.remove(CABECERA_CORREO);
                    cabeceras.remove(CABECERA_ROL);
                }))
                .build();

        if (esPublica(metodo, ruta)) {
            return chain.filter(limpio);
        }

        String cabecera = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (cabecera == null || !cabecera.startsWith("Bearer ")) {
            return responder(exchange, HttpStatus.UNAUTHORIZED, "Debes iniciar sesión: falta el token");
        }

        Claims claims;
        try {
            // revisa la firma y la vigencia
            claims = Jwts.parser().verifyWith(clave).build()
                    .parseSignedClaims(cabecera.substring(7))
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            return responder(exchange, HttpStatus.UNAUTHORIZED, "El token no es válido o ya venció");
        }

        if (!"acceso".equals(claims.get("tipo", String.class))) {
            return responder(exchange, HttpStatus.UNAUTHORIZED, "Usa el token de acceso, no el de renovación");
        }

        String rol = claims.get("rol", String.class);
        if (!tienePermiso(metodo, ruta, rol)) {
            return responder(exchange, HttpStatus.FORBIDDEN, "Tu rol no tiene permiso para esta acción");
        }

        // el microservicio recibe quién hace la petición (por ejemplo, MS-Reservas lo usa
        // para que un inquilino reserve y vea solo a su nombre)
        ServerWebExchange conUsuario = limpio.mutate()
                .request(peticion -> peticion
                        .header(CABECERA_CORREO, claims.getSubject())
                        .header(CABECERA_ROL, rol))
                .build();
        return chain.filter(conUsuario);
    }

    // Lo que se puede usar sin iniciar sesión
    private boolean esPublica(HttpMethod metodo, String ruta) {
        if (HttpMethod.OPTIONS.equals(metodo)) {
            return true; // consulta previa de CORS del navegador
        }
        if (ruta.startsWith("/v3/api-docs") || ruta.startsWith("/swagger-ui") || ruta.startsWith("/webjars")) {
            return true; // documentación de Swagger
        }
        if (ruta.equals("/api/v1/auth/registro") || ruta.equals("/api/v1/auth/login")
                || ruta.equals("/api/v1/auth/refresh")) {
            return true;
        }
        if (HttpMethod.GET.equals(metodo) && ruta.startsWith("/api/v1/propiedades")) {
            return true; // el catálogo lo ve cualquier visitante
        }
        if (HttpMethod.POST.equals(metodo) && ruta.equals("/api/v1/contacto")) {
            return true; // cualquier visitante puede escribir por el formulario de contacto
        }
        return HttpMethod.POST.equals(metodo) && ruta.equals("/api/v1/precios/calcular");
    }

    // Reglas por rol (lista 2, punto 3). Lo que no está permitido aquí queda solo para ADMIN.
    private boolean tienePermiso(HttpMethod metodo, String ruta, String rol) {
        if ("ADMIN".equals(rol)) {
            return true;
        }
        if (ruta.equals("/api/v1/auth/me")) {
            return true; // cualquier usuario con sesión ve sus propios datos
        }
        if (ruta.startsWith("/api/v1/reservas")) {
            if (HttpMethod.POST.equals(metodo)) {
                return "INQUILINO".equals(rol); // crear una reserva
            }
            if (HttpMethod.GET.equals(metodo)) {
                return "INQUILINO".equals(rol) || "ANFITRION".equals(rol); // ver reservas
            }
        }
        return false;
    }

    // "/propiedades/api/v1/propiedades" se revisa como "/api/v1/propiedades"
    private String rutaReal(String ruta) {
        for (String prefijo : PREFIJOS_DOCS) {
            if (ruta.startsWith(prefijo + "/")) {
                return ruta.substring(prefijo.length());
            }
        }
        return ruta;
    }

    private Mono<Void> responder(ServerWebExchange exchange, HttpStatus estado, String mensaje) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(estado);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] cuerpo = ("{\"status\":" + estado.value() + ",\"mensaje\":\"" + mensaje + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(cuerpo)));
    }

    // se ejecuta antes que los filtros de enrutamiento
    @Override
    public int getOrder() {
        return -1;
    }
}