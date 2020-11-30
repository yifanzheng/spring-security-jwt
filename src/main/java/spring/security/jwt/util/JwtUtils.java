package spring.security.jwt.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import spring.security.jwt.constant.JwtConstants;
import spring.security.jwt.constant.UserRoleConstants;

import javax.xml.bind.DatatypeConverter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Jwt 工具类，用于生成、解析与验证 token
 *
 * @author star
 **/
public final class JwtUtils {

    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);

    private static final byte[] SECRET_KEY = DatatypeConverter.parseBase64Binary(JwtConstants.SECRET_KEY);

    private JwtUtils() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }

    /**
     * 根据用户名和用户角色生成 token
     *
     * @param userName   用户名
     * @param roles      用户角色
     * @param isRemember 是否记住我
     * @return 返回生成的 token
     */
    public static String createToken(String userName, List<String> roles, long createTime, boolean isRemember) {
        // 过期时间
        long expiration = isRemember ? JwtConstants.EXPIRE_REMEMBER_TIME : JwtConstants.EXPIRE_TIME;
        // 生成 token
        return Jwts.builder()
                // 生成签证信息
                .setHeaderParam("typ", JwtConstants.TYPE)
                .signWith(Keys.hmacShaKeyFor(SECRET_KEY), SignatureAlgorithm.HS256)
                .setSubject(userName)
                .claim(JwtConstants.ROLE_CLAIM, roles)
                .claim(JwtConstants.CREATE_TIME_CLAIM, createTime)
                .setIssuer(JwtConstants.ISSUER)
                .setIssuedAt(new Date())
                .setAudience(JwtConstants.AUDIENCE)
                // 设置有效时间
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .compact();
    }

    /**
     * 验证 token 是否有效
     *
     * <p>
     * 如果解析失败，说明 token 是无效的
     *
     * @param token token 信息
     * @return 如果返回 true，说明 token 有效
     */
    public static boolean validateToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (UnsupportedJwtException e) {
            log.warn("Request to parse unsupported JWT[{}] failed: {}", token, e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("Request to parse invalid JWT[{}] failed: {}", token, e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("Request to parse empty or null JWT[{}] failed: {}", token, e.getMessage());
        }
        return false;
    }

    /**
     * 根据 token 获取用户认证信息
     *
     * @param token token 信息
     * @return 返回用户认证信息
     */
    public static Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        // 获取用户角色字符串
        List<String> roles = claims.get(JwtConstants.ROLE_CLAIM, List.class);
        List<SimpleGrantedAuthority> authorities =
                Objects.isNull(roles) ? Collections.singletonList(new SimpleGrantedAuthority(UserRoleConstants.ROLE_USER)) :
                        roles.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList());
        // 获取用户名
        String userName = claims.getSubject();

        return new UsernamePasswordAuthenticationToken(userName, token, authorities);

    }

    private static Claims getClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

}
