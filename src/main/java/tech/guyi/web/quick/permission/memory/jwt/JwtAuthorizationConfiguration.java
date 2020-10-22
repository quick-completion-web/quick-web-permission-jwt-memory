package tech.guyi.web.quick.permission.memory.jwt;

import lombok.Data;

@Data
public class JwtAuthorizationConfiguration {

    private String secret = "quick-web-permission";
    private String issUser = "quick-web";

}
