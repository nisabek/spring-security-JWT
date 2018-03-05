package proto.userservice.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import proto.userservice.CustomUserDetailsService;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class JWTConfiguration {
    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private CustomUserDetailsService userDetailsService;
    @Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(tokenEnhancer());
    }

    @Bean
    public TokenEnhancerChain tokenEnhancerChain(){
        final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        List tokenEnhancerList = new ArrayList();
        tokenEnhancerList.add(new CustomTokenConverter());
        tokenEnhancerList.add(tokenEnhancer());

        tokenEnhancerChain.setTokenEnhancers(tokenEnhancerList);
        return tokenEnhancerChain;
    }

    // this is to sign the JWT.
    @Bean
    public JwtAccessTokenConverter tokenEnhancer(){
        final JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setAccessTokenConverter(defaultAccessTokenConverter());

        jwtAccessTokenConverter.setSigningKey("super_secret_key_for_signature");

        return jwtAccessTokenConverter;
    }

    // THis is used when extracting data from JWT token. userDetailsService is set to be able to load the user back as
    //authenticated principal.
    @Bean
    public DefaultAccessTokenConverter defaultAccessTokenConverter(){
        DefaultAccessTokenConverter converter = new DefaultAccessTokenConverter();

        DefaultUserAuthenticationConverter userConverter = new DefaultUserAuthenticationConverter();
        userConverter.setUserDetailsService(userDetailsService);

        converter.setUserTokenConverter(userConverter);

        return converter;
    }

    @Bean
    @Primary
    public AuthorizationServerTokenServices defaultTokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setClientDetailsService(clientDetailsService);
        defaultTokenServices.setTokenEnhancer(tokenEnhancerChain());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }
}
