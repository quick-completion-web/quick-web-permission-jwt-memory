package tech.guyi.web.quick.permission.memory.jwt;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.jsonwebtoken.*;
import org.springframework.util.DigestUtils;
import tech.guyi.web.quick.permission.authorization.AuthorizationInfo;
import tech.guyi.web.quick.permission.authorization.memory.AuthorizationInfoMemory;
import tech.guyi.web.quick.permission.configuration.PermissionConfiguration;

import javax.annotation.Resource;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

public class JwtAuthorizationInfoMemory implements AuthorizationInfoMemory {

    private final Gson gson = new Gson();

    @Resource
    private PermissionConfiguration permissionConfiguration;
    @Resource
    private JwtAuthorizationConfiguration configuration;

    private SecretKey generalKey() {
        byte[] encodedKey = configuration.getSecret().getBytes();
        return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
    }

    private Optional<Claims> parse(String jwt) {
        SecretKey key = generalKey();
        try {
            return Optional.of(
                    Jwts.parser()
                            .setSigningKey(key)
                            .parseClaimsJws(jwt)
                            .getBody()
            );
        }catch (ExpiredJwtException e){
            return Optional.empty();
        }
    }

    private JwtBuilder getJwtBuilder(Map<String,Object> body){
        long now = System.currentTimeMillis();
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        SecretKey key = generalKey();
        body.put("timeout",now + permissionConfiguration.getAuthorization().getTimeout());
        JwtBuilder builder = Jwts.builder()
                .setId(DigestUtils.md5DigestAsHex(String.valueOf(now).getBytes()))
                .setIssuedAt(new Date(now))
                .setIssuer(configuration.getIssUser())
                .signWith(signatureAlgorithm, key)
                .setClaims(body);
        if (permissionConfiguration.getAuthorization().getTimeout() != -1){
            builder.setExpiration(new Date(now + permissionConfiguration.getAuthorization().getTimeout()));
        }
        return builder;
    }

    @Override
    public String forType() {
        return "jwt";
    }

    @Override
    public boolean contains(String key) {
        return this.parse(key).isPresent();
    }

    @Override
    public <A extends AuthorizationInfo> String save(A authorization, long timespan) {
        String json = gson.toJson(authorization);
        Map<String,Object> claims = gson.fromJson(json,new TypeToken<Map<String,Object>>(){}.getType());
        claims.put("classes",authorization.getClass().getName());
        return this.getJwtBuilder(claims).compact();
    }

    @Override
    public void remove(String key) {

    }

    @Override
    public Optional<AuthorizationInfo> get(String key) {
        return this.parse(key)
                .map(claims -> {
                    String json = gson.toJson(claims);
                    try {
                        Class<? extends AuthorizationInfo> classes = (Class<? extends AuthorizationInfo>) Class.forName(claims.get("classes").toString());
                        return gson.fromJson(json,classes);
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                    return null;
                });
    }

    @Override
    public String renew(String key) {
        return parse(key).map(claims -> {
            long now = System.currentTimeMillis();
            long timeout = Optional.ofNullable(claims.get("timeout"))
                    .map(Object::toString)
                    .map(Long::valueOf)
                    .orElse(now);
            if ((timeout - now) < (permissionConfiguration.getAuthorization().getTimeout() * 0.5)){
                return this.getJwtBuilder(claims).compact();
            }
            return key;
        }).orElse(key);
    }

}
