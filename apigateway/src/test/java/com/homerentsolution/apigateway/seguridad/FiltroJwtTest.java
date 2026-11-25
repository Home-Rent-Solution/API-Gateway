package com.homerentsolution.apigateway.seguridad;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

// Pruebas de la seguridad del Gateway: la tabla de permisos por rol (lista 2, punto 3)
// y los casos de token inválido. No levantan servicios: una cadena simulada hace de
// microservicio y guarda la petición que le llega.
class FiltroJwtTest {

    private static final String SECRETO = "secreto-de-prueba-para-el-filtro-del-gateway-123";

    private final FiltroJwt filtro = new FiltroJwt(SECRETO);

    // la petición que llegó al "microservicio"; queda en null si el filtro la bloqueó
    private final AtomicReference<ServerWebExchange> recibida = new AtomicReference<>();
    private final GatewayFilterChain microservicio = exchange -> {
        recibida.set(exchange);
        return Mono.empty();
    };

    // código con que respondió el filtro (null si dejó pasar la petición)
    private Integer codigo;

    @BeforeEach
    void limpiar() {
        recibida.set(null);
        codigo = null;
    }

    private String token(String rol, String tipo, String secreto, long segundosDeVida) {
        Instant ahora = Instant.now();
        return Jwts.builder()
                .subject("usuario@duoc.cl")
                .claim("rol", rol)
                .claim("tipo", tipo)
                .issuedAt(Date.from(ahora))
                .expiration(Date.from(ahora.plusSeconds(segundosDeVida)))
                .signWith(Keys.hmacShaKeyFor(secreto.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    private String acceso(String rol) {
        return token(rol, "acceso", SECRETO, 900);
    }

    // Pasa la petición por el filtro, como haría el Gateway
    private void enviar(HttpMethod metodo, String ruta, String token, String... cabecerasExtra) {
        recibida.set(null);
        MockServerHttpRequest.BodyBuilder peticion = MockServerHttpRequest.method(metodo, ruta);
        if (token != null) {
            peticion.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        for (int i = 0; i < cabecerasExtra.length; i += 2) {
            peticion.header(cabecerasExtra[i], cabecerasExtra[i + 1]);
        }
        MockServerWebExchange exchange = MockServerWebExchange.from(peticion);
        filtro.filter(exchange, microservicio).block();
        codigo = exchange.getResponse().getStatusCode() == null ? null : exchange.getResponse().getStatusCode().value();
    }

    private void debePasar() {
        assertNotNull(recibida.get(), "la petición debía llegar al microservicio");
        assertNull(codigo);
    }

    private void debeResponder(int esperado) {
        assertNull(recibida.get(), "la petición no debía llegar al microservicio");
        assertEquals(esperado, codigo);
    }

    // ===== Tabla de permisos por rol =====

    @Test
    void verPropiedades_esPublico() {
        enviar(HttpMethod.GET, "/api/v1/propiedades", null);
        debePasar();
    }

    @Test
    void crearPropiedades_soloAdmin() {
        enviar(HttpMethod.POST, "/api/v1/propiedades", null);
        debeResponder(401);
        enviar(HttpMethod.POST, "/api/v1/propiedades", acceso("INQUILINO"));
        debeResponder(403);
        enviar(HttpMethod.POST, "/api/v1/propiedades", acceso("ANFITRION"));
        debeResponder(403);
        enviar(HttpMethod.POST, "/api/v1/propiedades", acceso("ADMIN"));
        debePasar();
    }

    @Test
    void eliminarPropiedades_soloAdmin() {
        enviar(HttpMethod.DELETE, "/api/v1/propiedades/1", acceso("ANFITRION"));
        debeResponder(403);
        enviar(HttpMethod.DELETE, "/api/v1/propiedades/1", acceso("ADMIN"));
        debePasar();
    }

    @Test
    void crearReserva_inquilinoYAdmin() {
        enviar(HttpMethod.POST, "/api/v1/reservas", null);
        debeResponder(401);
        enviar(HttpMethod.POST, "/api/v1/reservas", acceso("ANFITRION"));
        debeResponder(403);
        enviar(HttpMethod.POST, "/api/v1/reservas", acceso("INQUILINO"));
        debePasar();
        enviar(HttpMethod.POST, "/api/v1/reservas", acceso("ADMIN"));
        debePasar();
    }

    @Test
    void verReservas_conSesion() {
        enviar(HttpMethod.GET, "/api/v1/reservas", null);
        debeResponder(401);
        enviar(HttpMethod.GET, "/api/v1/reservas", acceso("INQUILINO"));
        debePasar();
        enviar(HttpMethod.GET, "/api/v1/reservas/1", acceso("ANFITRION"));
        debePasar();
    }

    @Test
    void usuarios_soloAdmin() {
        enviar(HttpMethod.GET, "/api/v1/usuarios", acceso("INQUILINO"));
        debeResponder(403);
        enviar(HttpMethod.GET, "/api/v1/usuarios", acceso("ANFITRION"));
        debeResponder(403);
        enviar(HttpMethod.GET, "/api/v1/usuarios", acceso("ADMIN"));
        debePasar();
    }

    @Test
    void loginYRegistro_sonPublicos_yMeNecesitaSesion() {
        enviar(HttpMethod.POST, "/api/v1/auth/login", null);
        debePasar();
        enviar(HttpMethod.POST, "/api/v1/auth/registro", null);
        debePasar();
        enviar(HttpMethod.GET, "/api/v1/auth/me", null);
        debeResponder(401);
        enviar(HttpMethod.GET, "/api/v1/auth/me", acceso("INQUILINO"));
        debePasar();
    }

    @Test
    void contacto_enviarEsPublico_verEsSoloAdmin() {
        enviar(HttpMethod.POST, "/api/v1/contacto", null);
        debePasar();
        enviar(HttpMethod.GET, "/api/v1/contacto", null);
        debeResponder(401);
        enviar(HttpMethod.GET, "/api/v1/contacto", acceso("INQUILINO"));
        debeResponder(403);
    }

    // ===== Tokens inválidos =====

    @Test
    void tokenDeRenovacion_noSirveParaEntrar() {
        enviar(HttpMethod.GET, "/api/v1/auth/me", token("ADMIN", "renovacion", SECRETO, 900));
        debeResponder(401);
    }

    @Test
    void tokenFirmadoConOtraClave_esRechazado() {
        String falso = token("ADMIN", "acceso", "otra-clave-secreta-que-no-es-la-del-gateway-999", 900);
        enviar(HttpMethod.GET, "/api/v1/usuarios", falso);
        debeResponder(401);
    }

    @Test
    void tokenVencido_esRechazado() {
        enviar(HttpMethod.GET, "/api/v1/auth/me", token("INQUILINO", "acceso", SECRETO, -60));
        debeResponder(401);
    }

    // ===== Rutas de documentación =====

    @Test
    void rutaDeDocumentacion_noSirveDeAtajo() {
        // /propiedades/... llega al mismo microservicio que /api/v1/propiedades
        enviar(HttpMethod.POST, "/propiedades/api/v1/propiedades", null);
        debeResponder(401);
    }

    @Test
    void documentacionDeSwagger_esPublica() {
        enviar(HttpMethod.GET, "/propiedades/v3/api-docs", null);
        debePasar();
    }

    // ===== Cabeceras con los datos del usuario (B-11) =====

    @Test
    void cabecerasDelUsuario_salenDelToken_yNoDelCliente() {
        // un inquilino intenta hacerse pasar por administrador
        enviar(HttpMethod.GET, "/api/v1/reservas", acceso("INQUILINO"),
                "X-Usuario-Rol", "ADMIN", "X-Usuario-Correo", "admin@duoc.cl");
        debePasar();
        HttpHeaders cabeceras = recibida.get().getRequest().getHeaders();
        assertEquals("INQUILINO", cabeceras.getFirst("X-Usuario-Rol"));
        assertEquals("usuario@duoc.cl", cabeceras.getFirst("X-Usuario-Correo"));
    }

    @Test
    void enRutasPublicas_lasCabecerasFalsasSeBorran() {
        enviar(HttpMethod.GET, "/api/v1/propiedades", null, "X-Usuario-Rol", "ADMIN");
        debePasar();
        assertNull(recibida.get().getRequest().getHeaders().getFirst("X-Usuario-Rol"));
    }
}
