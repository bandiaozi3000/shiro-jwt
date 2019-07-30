### 一.Shiro登录流程

#####    1.获取Subject对象和UsernamePasswordToken对象,调用subject.login().

```java
 Subject subject = SecurityUtils.getSubject(); 
        try {
            UsernamePasswordToken token = new             UsernamePasswordToken(loginInfo.getUsername(), loginInfo.getPassword());
            subject.login(token);
```

#####    2.subject.login()执行流程

​       1)调用securityManager的login方法

```java
Subject subject = this.securityManager.login(this, token);
```

​      2)调用securityManager的authenticate方法

```java
 info = this.authenticate(token);
```

​      3)调用AuthenticatingSecurityManager的authenticate方法

```java
/**
 * 其中,authenticator在ShiroConfig中配置
 *  @Bean
    public Authenticator authenticator(UserService userService) {
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        authenticator.setRealms(Arrays.asList(jwtShiroRealm(userService),     dbShiroRealm(userService)));
        authenticator.setAuthenticationStrategy(new FirstSuccessfulStrategy());
        return authenticator;
    }
 */

    public AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {
        return this.authenticator.authenticate(token);
    }
```

​      4)调用父类AbstractAuthenticator的authenticate方法

```java
   info = this.doAuthenticate(token)
```

​        方法实现:

```java
protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        this.assertRealmsConfigured();
        Collection<Realm> realms = this.getRealms();
        return realms.size() == 1 ? this.doSingleRealmAuthentication((Realm)realms.iterator().next(), authenticationToken) : this.doMultiRealmAuthentication(realms, authenticationToken);
    }
```

​        其中,  realms中有两个值,DbShiroRealm和JWTShiroRealm是在ShiroConfig中配置的

```java
 @Bean
    public Authenticator authenticator(UserService userService) {
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        authenticator.setRealms(Arrays.asList(jwtShiroRealm(userService), dbShiroRealm(userService)));
        authenticator.setAuthenticationStrategy(new FirstSuccessfulStrategy());
        return authenticator;
    }
```

​       5)判断realms大小,若为1,执行doSingleRealmAuthentication,若大于1,执行doMultiRealmAuthentication.配置了两个realm,所以此处执行doMultiRealmAuthentication      

```java
  /**
    判断当前realm是否支持当前token,判断是否支持在创建该Realm时重写父类supports方法 
	@Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }
  */
  if (realm.supports(token)) {
  
  /**
    进入方法后,核心方法为:
    info = this.doGetAuthenticationInfo(token)
    该方法即DbShiroRealm中重写的方法    
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection
	principals) {      
	}
  */
  info = realm.getAuthenticationInfo(token);
```

##### 3.DbShiroRealm中doGetAuthenticationInfo()方法

​       方法本身是判断当前对象是否存在,比对信息是否一致,则在SimpleAuthenticationInfo之后进行.

```java
return new SimpleAuthenticationInfo()
```

​       1）在执行完getAuthenticationInfo()方法后,执行assertCredentialsMatch()方法

```java
 this.assertCredentialsMatch(token, info)
```

​       方法实现:

```java
/**
 补充:此处的CredentialsMatcher可以自己定义,例如在JWTShiroRealm中  
    public JWTShiroRealm(UserService userService){
        this.userService = userService;
        this.setCredentialsMatcher(new JWTCredentialsMatcher());
    }
  JWTCredentialsMatcher即为自己定义的.
*/
CredentialsMatcher cm = this.getCredentialsMatcher();
/**
 token即为subject.login(token)中传入的,info为创建 SimpleAuthenticationInfo传入的第一个参数,即doGetAuthenticationInfo中根据用户名获取到的对象信息,比对即是将此两对象作比较.比较的值为SimpleAuthenticationInfo传入的第二个参数,一般比较的是密码.
*/
if (!cm.doCredentialsMatch(token, info)) {
```

```java
public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        Object tokenHashedCredentials = this.hashProvidedCredentials(token, info);
        Object accountCredentials = this.getCredentials(info);
        return this.equals(tokenHashedCredentials, accountCredentials);
    }
```

​    若比对结果为true,则验证身份成功.以上即为大概流程.

### 二.Shiro配置文件

##### 1.配置Authenticator

```java
  /**
  authenticator.setRealms()即为自己配置的Realm实现类.
  */
@Bean
    public Authenticator authenticator(UserService userService) {
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        authenticator.setRealms(Arrays.asList(jwtShiroRealm(userService), dbShiroRealm(userService)));
        authenticator.setAuthenticationStrategy(new FirstSuccessfulStrategy());
        return authenticator;
    }
```

##### 2.配置ShiroFilterFactoryBean

```java
/**
  配置过滤器:该过滤可以自己定义. factoryBean.setFilterChainDefinitionMap()中为下述配置的
  ShiroFilterChainDefinition
*/
@Bean("shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager, UserService userService) {
    	ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();
        factoryBean.setSecurityManager(securityManager);
        Map<String, Filter> filterMap = factoryBean.getFilters();
        filterMap.put("authcToken", createAuthFilter(userService));
        filterMap.put("anyRole", createRolesFilter());
        factoryBean.setFilters(filterMap);
        factoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition().getFilterChainMap());
        return factoryBean;
    }
```

如下即为自定义的过滤器:

```java
 protected JwtAuthFilter createAuthFilter(UserService userService){
        return new JwtAuthFilter(userService);
    }

    protected AnyRolesAuthorizationFilter createRolesFilter(){
        return new AnyRolesAuthorizationFilter();
    }
```

##### 3.配置ShiroFilterChainDefinition

```java
/**
  注意:"noSessionCreation,anon,authcToken",该值即为配置过滤器时factoryBean.setFilters
  中map的key值.
*/
@Bean
    protected ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        chainDefinition.addPathDefinition("/login", "noSessionCreation,anon,authcToken");
        chainDefinition.addPathDefinition("/logout", "noSessionCreation,authcToken[permissive]");
        chainDefinition.addPathDefinition("/image/**", "anon");
        //只允许admin或manager角色的用户访问
        chainDefinition.addPathDefinition("/admin/**", "noSessionCreation,authcToken,anyRole[admin,manager]");
        chainDefinition.addPathDefinition("/article/list", "noSessionCreation,authcToken");
        chainDefinition.addPathDefinition("/article/*", "noSessionCreation,authcToken[permissive]");
        chainDefinition.addPathDefinition("/**", "noSessionCreation,authcToken");
        return chainDefinition;
    }
```

### 三.认证登录流程

#####     1.根据ShiroFilterChainDefinition里路径配置,判断当前路径是否被过滤器拦截.

```java
 /**
  若被拦截,执行该方法.
 */
@Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) //对于OPTION请求做拦截，不做token校验
            return false;
        return super.preHandle(request, response);
    }
```

#####   2.被拦截执行过滤器重写父类的preHandle()方法

​         1)preHandle(request, response)方法实现:

```java
 /**
   this.appliedPaths：ShiroFilterChainDefinition中配置authcToken的路径.authcToken为过滤器
   map中当前filter(此处为JWTAuthFilter)的key值.
   遍历该路径集合,获取当前路径,执行isFilterChainContinued()方法.
 */
if (this.appliedPaths != null && !this.appliedPaths.isEmpty()) {
            Iterator var3 = this.appliedPaths.keySet().iterator();

            String path;
            do {
                if (!var3.hasNext()) {
                    return true;
                }

                path = (String)var3.next();
            } while(!this.pathsMatch(path, request));

            log.trace("Current requestURI matches pattern '{}'.  Determining filter chain execution...", path);
            Object config = this.appliedPaths.get(path);
            return this.isFilterChainContinued(request, response, path, config);
        }
```

​        2)isFilterChainContinued(request, response, path, config)方法实现:

```java
return this.onPreHandle(request, response, pathConfig);
/**
  onPreHandle方法实现，其中isAccessAllowed方法为创建的Filter中重写的方法.
*/
  return this.isAccessAllowed(request, response, mappedValue) || this.onAccessDenied(request, response, mappedValue);    
```

```java
/**
   1.if(this.isLoginRequest(request, response)):可以自己设置
   public JwtAuthFilter(UserService userService){
        this.userService = userService;
        this.setLoginUrl("/login");
    }
*/
@Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if(this.isLoginRequest(request, response))
            return true;
        Boolean afterFiltered = (Boolean)(request.getAttribute("jwtShiroFilter.FILTERED"));
        if( BooleanUtils.isTrue(afterFiltered))
        	return true;

        boolean allowed = false;
        try {
            allowed = executeLogin(request, response);
        } catch(IllegalStateException e){ //not found any token
            log.error("Not found any token");
        }catch (Exception e) {
            log.error("Error occurs when login", e);
        }
        return allowed || super.isPermissive(mappedValue);
    }
```

​        3)executeLogin(request, response)方法实现:

```java
/**
   根据此段代码不难发现,和subject.login()一样.该方法执行成功后,执行onLoginSuccess方法.该方法为自定义的filter中重写的父类方法.
   补充:在执行到assertCredentialsMatch方法是,可以看到此时的CredentialsMatcher为我们自定义的matcher.
    public JWTShiroRealm(UserService userService){
        this.userService = userService;
        this.setCredentialsMatcher(new JWTCredentialsMatcher());
    }
*/
protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        AuthenticationToken token = this.createToken(request, response);
        if (token == null) {
            String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken must be created in order to execute a login attempt.";
            throw new IllegalStateException(msg);
        } else {
            try {
                Subject subject = this.getSubject(request, response);
                subject.login(token);
                return this.onLoginSuccess(token, subject, request, response);
            } catch (AuthenticationException var5) {
                return this.onLoginFailure(token, var5, request, response);
            }
        }
    }
```

```java
/**
  自定义filter重写的onLoginSuccess方法.此处判断token是否有效以及是否需要刷新.
*/
@Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        String newToken = null;
        if(token instanceof JWTToken){
            JWTToken jwtToken = (JWTToken)token;
            UserDto user = (UserDto) subject.getPrincipal();
            boolean shouldRefresh = shouldTokenRefresh(JwtUtils.getIssuedAt(jwtToken.getToken()));
            if(shouldRefresh) {
                newToken = userService.generateJwtToken(user.getUsername());
            }
        }
        if(StringUtils.isNotBlank(newToken))
            httpResponse.setHeader("x-auth-token", newToken);

        return true;
    }
```

  执行成功后,filter放行,认证成功.以上即为认证登录流程.

### 四.角色配置

#####    1.执行完JwtAuthFilter后,会执行角色过滤器AnyRolesAuthorizationFilter.

```java
/**
   本段代码的作用为接着执行链.Chain:链.过滤器像链条一样,一个接着一个.一个执行完之后,继续执行下一个过滤器.注意:JwtAuthFilter继承AuthenticatingFilter认证.AnyRolesAuthorizationFilter继承AuthorizationFilter授权.
*/
this.executeChain(request, response, chain)
    
protected void executeChain(ServletRequest request, ServletResponse response, FilterChain chain) throws Exception {
        chain.doFilter(request, response); //继续执行过滤
    }
```

#####    2.doFilter方法实现

```java
 /**
    this.index:在执行过一次过滤器后,index会加1.初始为0,所以在经过两次过滤后，index为2
    Filters属性:1.NoSessionCreationFilter
               2.JWTAuthFilter
               3.AnyRolesAuthorizationFilter
    所以此时获取的Filter即为:AnyRolesAuthorizationFilter.
 */
public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        if (this.filters != null && this.filters.size() != this.index) {
            if (log.isTraceEnabled()) {
                log.trace("Invoking wrapped filter at index [" + this.index + "]");
            }

            ((Filter)this.filters.get(this.index++)).doFilter(request, response, this);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Invoking original filter chain.");
            }

            this.orig.doFilter(request, response);
        }

    }
```

#####   3.this.doFilterInternal(request, response, filterChain)方法实现:

```java
   /**
     每一步执行的核心代码:this.isAccessAllowed()即为AnyRolesAuthorizationFilter中重写的方法
   */
   this.doFilterInternal(request, response, filterChain)
       
   boolean continueChain = this.preHandle(request, response)
       
   return this.isFilterChainContinued(request, response, path, config)
       
   return this.onPreHandle(request, response, pathConfig);

   return this.isAccessAllowed(request, response, mappedValue) || this.onAccessDenied(request, response, mappedValue);
```

4.isAccessAllowed()方法实现:

```java
 /**
   核心:subject.hasRole(role).跳入该方法,发现底层实现为:
      1.this.authorizer.hasRole(principals, roleIdentifier)
      2.(!(realm instanceof Authorizer) || !((Authorizer)realm).hasRole(principals, roleIdentifier))
      3.info = this.doGetAuthorizationInfo(principals),该方法会跳入DbShiroRealm重写后的
      doGetAuthorizationInfo方法.该方法给subject添加角色.
    执行完后:subject的realmPrincipals会有相关角色.返回为true.过滤器放行,执行完毕.
 */
protected boolean isAccessAllowed(ServletRequest servletRequest, ServletResponse servletResponse, Object mappedValue) throws Exception {
    	Boolean afterFiltered = (Boolean)(servletRequest.getAttribute("anyRolesAuthFilter.FILTERED"));
        if( BooleanUtils.isTrue(afterFiltered))
        	return true;
        
        Subject subject = getSubject(servletRequest, servletResponse);
        String[] rolesArray = (String[]) mappedValue;
        if (rolesArray == null || rolesArray.length == 0) { //没有角色限制，有权限访问
            return true;
        }
        for (String role : rolesArray) {
            if (subject.hasRole(role)) //若当前用户是rolesArray中的任何一个，则有权限访问
                return true;
        }
        return false;
    }
```





















