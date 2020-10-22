package tech.guyi.web.quick.permission.memory.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtMemoryAutoConfiguration {

    @Bean
    @ConfigurationProperties(prefix = "tech.guyi.web.quick.permission.jwt")
    public JwtAuthorizationConfiguration jwtAuthorizationConfiguration(){
        return new JwtAuthorizationConfiguration();
    }

    @Bean
    public JwtAuthorizationInfoMemory jwtAuthorizationInfoMemory(){
        return new JwtAuthorizationInfoMemory();
    }

}
