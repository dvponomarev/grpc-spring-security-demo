package com.revinate.grpcspringsecurity.util;

import io.grpc.Attributes;
import io.grpc.CallCredentials;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;

import java.util.concurrent.Executor;

/**
 * https://tools.ietf.org/html/rfc6749#section-7.1
 * https://tools.ietf.org/html/rfc6750
 */
public final class Oauth2CutAuthenticationCallCredentials implements CallCredentials {

    private final String accessToken;

    public Oauth2CutAuthenticationCallCredentials(String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public void applyRequestMetadata(MethodDescriptor<?, ?> method, Attributes attrs, Executor appExecutor, MetadataApplier applier) {
        Metadata metadata = new Metadata();
        metadata.put(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + accessToken);
        applier.apply(metadata);
    }

    @Override
    public void thisUsesUnstableApi() {
    }

}
