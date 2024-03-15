package io.flux.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor
public class JsonWebTokenHeader {
    private final JWSHeader header;
}
