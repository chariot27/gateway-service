package br.ars.gateway_service.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/fallback")
public class FallbackController {

    @GetMapping("/user")
    public ResponseEntity<String> userFallback() {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body("⛔ Serviço de usuários indisponível no momento. Tente novamente mais tarde.");
    }

    @GetMapping("/match")
    public ResponseEntity<String> matchFallback() {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body("⛔ Serviço de match fora do ar. Estamos trabalhando para resolver.");
    }

    @GetMapping("/checkout")
    public ResponseEntity<String> checkoutFallback() {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body("⛔ Checkout temporariamente indisponível. Tente novamente em instantes.");
    }

    @GetMapping("/subscription")
    public ResponseEntity<String> subscriptionFallback() {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body("⛔ Serviço de assinatura inativo no momento. Por favor, aguarde.");
    }
}
