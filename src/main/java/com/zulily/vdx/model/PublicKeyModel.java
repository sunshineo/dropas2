package com.zulily.vdx.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import java.sql.Timestamp;

/**
 * @author ssun
 * The model for parcel tracking.
 */
@Entity
@Table(name = "publicKey")
@JsonIgnoreProperties(ignoreUnknown = true)
public class PublicKeyModel {
    @JsonProperty
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public long publicKeyId;

    @NotNull
    @JsonProperty
    @Column(name = "as2Id", nullable = false)
    public String as2Id;

    @NotNull
    @JsonProperty
    @Column(name = "publicKey", nullable = false)
    public String publicKey;

    @JsonProperty
    @Column(name = "createdAt", nullable = false)
    public Timestamp createdAt;

    @JsonProperty
    @Column(name = "updatedAt", nullable = false, updatable = false,
            columnDefinition="TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP")
    public Timestamp updatedAt;
}
