package spring.security.jwt.utils;

import spring.security.jwt.constants.SecurityConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.xml.bind.DatatypeConverter;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Jwt 工具类，用于生成和解析 token
 *
 * @author star
 **/
public final class JwtUtils {

    private JwtUtils() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }

    /**
     * 根据用户名生成 token
     *
     * @param username   用户名
     * @param roles      用户角色
     * @param isRemember 是否记住我
     * @return 返回生成的 token
     */
    public static String generateToken(String username, List<String> roles, boolean isRemember) {
        byte[] jwtSecretKey = DatatypeConverter.parseBase64Binary(SecurityConstants.JWT_SECRET_KEY);
        // 过期时间
        long expiration = isRemember ? SecurityConstants.EXPIRATION_REMEMBER_TIME : SecurityConstants.EXPIRATION_TIME;
        // 生成 token
        String token = Jwts.builder()
                // 生成签证信息
                .setHeaderParam("typ", SecurityConstants.TOKEN_TYPE)
                .signWith(Keys.hmacShaKeyFor(jwtSecretKey), SignatureAlgorithm.HS256)
                .setSubject(username)
                .claim(SecurityConstants.TOKEN_ROLE_CLAIM, roles)
                .setIssuer(SecurityConstants.TOKEN_ISSUER)
                .setIssuedAt(new Date())
                .setAudience(SecurityConstants.TOKEN_AUDIENCE)
                // 设置有效时间
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .compact();
        // jwt 前面一般都会加 Bearer，在请求头里加入 Authorization，并加上 Bearer 标注
        return SecurityConstants.TOKEN_PREFIX + token;
    }

    /**
     * 验证 token，返回结果
     *
     * <p>
     * 如果解析失败，说明 token 是无效的
     */
    private static Claims validateToken(String token) {
        byte[] secretKey = DatatypeConverter.parseBase64Binary(SecurityConstants.JWT_SECRET_KEY);

        if (StringUtils.isEmpty(token)) {
            throw new RuntimeException("Miss token");
        }

        return Jwts.parser()
                .setSigningKey(Keys.hmacShaKeyFor(secretKey))
                .parseClaimsJws(token)
                .getBody();
    }

    public static String getUsername(String token) {
        Claims claims = validateToken(token);

        return claims.getSubject();
    }

    public static List<GrantedAuthority> getRoles(String token) {
        List<?> roles = (List<?>) validateToken(token).get(SecurityConstants.TOKEN_ROLE_CLAIM);
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority((String) role))
                .collect(Collectors.toList());


    }

}
