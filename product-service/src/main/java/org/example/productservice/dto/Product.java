package org.example.productservice.dto;

import java.math.BigDecimal;

public record Product(Long id, String name, BigDecimal price) {
}
