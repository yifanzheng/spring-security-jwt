# springboot实现jwt授权
授权的方法有很多种，无非就是通过ID和Role来区分用户。因为JWT的灵活性，于是可以把用户ID或用户的角色放到jwt里面。因为用户请求api都会附带上jwt, 也就相当于直接附带上了用户ID或用户的角色。

### 将用户的信息加入jwt中
只需要在生成JWT之前，用key-value的形式添加进JWT的claims就行. 比如 map.put("userId","1")，map.put("role","admin")。
```java
public static String generateToken(String username){
    HashMap<String, Object> map = new HashMap<>();
    //将用户名当作角色role信息，可以put任意的数据
    map.put(ROLE,username);
    //生成jwt字符串
    String jwt = Jwts.builder()
            .setClaims(map)
            .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))//设置有效时间为100hours
            .signWith(SignatureAlgorithm.HS512, SECRET)//生成签证信息
            .compact();
    return TOKEN_PREFIX+jwt;//jwt前面一般都会加Bearer;一般是在请求头里加入Authorization，并加上Bearer标注
}
```
### 将解码jwt后的Role信息放入Header
在jwt使用用户的信息不是很方便，因为在通过api请求拿到的是jwt字符串，需要额外解析以后才能使用。但是我们可以在验证jwt时，把解码得到的用户信息放入请求HttpServletRequest的Header里面（Header "ROLE":"admin"），这样就可以在Header里面得到用户的信息。
```java
 /**
  * 验证token，并将role信息添加到请求头
  * @param request
  * @return
  */
public static HttpServletRequest validateTokenAndAddRoleToHeader(HttpServletRequest request) {
    String token = request.getHeader(AUTO_HEADER);
    if (token != null) {
        // 解析token
        try {
            Map<String, Object> body = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                    .getBody();
            //使用代理模式重写getHeades方法
            HttpServletRequest requestPoxy = (HttpServletRequest)Proxy.newProxyInstance(request.getClass().getClassLoader(), request.getClass().getInterfaces(), new InvocationHandler() {
                        @Override
                        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                            //获取方法名
                            String methodName= method.getName();
                            if (Objects.equals(methodName,"getHeaders")) {
                                String key = String.valueOf(args[0]);

                                if(body!=null&&body.containsKey(key)){
                                    //如果jwt存在这个数据，就直接返回
                                    //注意，getHeaders()返回值类型是Enumeration<String>，故要转换
                                    return Collections.enumeration(Arrays.asList(body.get(key)));
                                }
                            }
                            return method.invoke(request,args);
                        }
                    }
            );
            return requestPoxy;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    } else {
        throw new RuntimeException("Missing token");
    }
}
```
### 验证效果
```java
@GetMapping("/api/success")
public Object success(@RequestHeader(value ="ROLE") String role){
    return "Login success! Wellcome "+role;
}
```
![jwt](/images/3.png)
![jwt](/images/4.png)



