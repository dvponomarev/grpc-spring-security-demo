package com.revinate.grpcspringsecurity.grpc.interceptor;

import io.grpc.*;
import lombok.extern.slf4j.Slf4j;
import org.lognet.springboot.grpc.GRpcGlobalInterceptor;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

import java.util.Collections;
import java.util.Objects;
import java.util.UUID;

import static com.google.common.base.Strings.nullToEmpty;

/**
 * https://tools.ietf.org/html/rfc6749#section-7.1
 * https://tools.ietf.org/html/rfc6750
 */
@GRpcGlobalInterceptor
@Order(80)
@Slf4j
public class Oauth2CutAuthInterceptor implements ServerInterceptor {

    /** Api key, actually. */
    private String accessToken = "abc123";


    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call,
            Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {
        String authHeader = nullToEmpty(headers.get(Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER)));
        if (!(authHeader.startsWith("Bearer ") || authHeader.startsWith("bearer "))) {
            return next.startCall(call, headers);
        }

        try {
            String token = authHeader.substring(7);

            log.debug("Bearer Token Authorization header found");

            if (authenticationIsRequired()) {
                if (Objects.equals(token, accessToken)) {
                    log.debug("Authentication success with permanent access token");

                    SecurityContextHolder.getContext().setAuthentication(
                            new AnonymousAuthenticationToken(
                                    UUID.randomUUID().toString(), "a_user",
                                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"))
                            )
                    );
                }
            }
        } catch (AuthenticationException | OAuth2Exception e) {
            SecurityContextHolder.clearContext();

            log.debug("Authentication request failed: {}", e.getMessage());

            throw Status.UNAUTHENTICATED.withDescription(e.getMessage()).withCause(e).asRuntimeException();
        }

        return next.startCall(call, headers);
    }

    private boolean authenticationIsRequired() {
        final Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        return Objects.isNull(existingAuth) || !existingAuth.isAuthenticated();

    }
}
