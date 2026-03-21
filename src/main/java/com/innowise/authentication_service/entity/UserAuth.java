package com.innowise.authentication_service.entity;


import com.innowise.authentication_service.entity.enums.AuthRole;
import jakarta.persistence.*;
import lombok.*;

@EqualsAndHashCode(callSuper = true)
@Entity
@Data
@AllArgsConstructor
@Table(name = "users")
@NoArgsConstructor
@Builder
public class UserAuth extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String login;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private AuthRole role = AuthRole.USER;
}
