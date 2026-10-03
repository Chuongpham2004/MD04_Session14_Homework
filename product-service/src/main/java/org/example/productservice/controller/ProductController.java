package org.example.productservice.controller;

import org.example.productservice.dto.Product;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    // Dữ liệu giả (static list) - không dùng Database
    private final List<Product> products = new CopyOnWriteArrayList<>(List.of(
            new Product(1L, "iPhone 15", new BigDecimal("24990000")),
            new Product(2L, "Samsung Galaxy S24", new BigDecimal("21990000")),
            new Product(3L, "MacBook Air M3", new BigDecimal("27990000"))
    ));

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public List<Product> getAll() {
        return new ArrayList<>(products);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable Long id, Authentication authentication) {
        boolean removed = products.removeIf(p -> p.id().equals(id));
        if (!removed) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "Product " + id + " not found"));
        }
        return ResponseEntity.ok(Map.of(
                "message", "Product " + id + " deleted successfully",
                "deletedBy", authentication.getName()));
    }
}
