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
     * 根据用户名生成token
     *
     * @return
     */
    public static String generateToken(String username, List<String> roles) {
        byte[] jwtSecretKey = DatatypeConverter.parseBase64Binary(SecurityConstants.JWT_SECRET_KEY);
        String token = Jwts.builder()
                // 生成签证信息
                .setHeaderParam("typ", SecurityConstants.TOKEN_TYPE)
                .signWith(Keys.hmacShaKeyFor(jwtSecretKey), SignatureAlgorithm.HS256)
                .setSubject(username)
                .claim(SecurityConstants.TOKEN_ROL_CLAIM, roles)
                .setIssuer(SecurityConstants.TOKEN_ISSUER)
                .setIssuedAt(new Date())
                .setAudience(SecurityConstants.TOKEN_AUDIENCE)
                // 设置有效时间
                .setExpiration(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME * 1000))
                .compact();
        // jwt 前面一般都会加 Bearer，在请求头里加入 Authorization，并加上 Bearer 标注
        return SecurityConstants.TOKEN_PREFIX + token;
    }

    /**
     * 验证 token，返回结果。
     * 如果解析失败，说明 token 是无效的
     *
     * @return
     */
    private static Claims validateToken(String token) {
        byte[] secretKey = DatatypeConverter.parseBase64Binary(SecurityConstants.JWT_SECRET_KEY);

        if (StringUtils.isEmpty(token)) {
          throw new RuntimeException("Miss token");
        }
        Claims body = Jwts.parser()
                .setSigningKey(Keys.hmacShaKeyFor(secretKey))
                .parseClaimsJws(token)
                .getBody();

        return body;
    }

    public static String getUsername(String token) {
        Claims claims = validateToken(token);
        String username = claims.getSubject();
        return username;
    }

    public static List<GrantedAuthority> getRoles(String token) {
        List<?> roles = (List<?>)validateToken(token).get(SecurityConstants.TOKEN_ROL_CLAIM);
        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority((String) role))
                .collect(Collectors.toList());
        return authorities;
    }

}
