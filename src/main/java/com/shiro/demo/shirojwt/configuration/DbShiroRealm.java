package com.shiro.demo.shirojwt.configuration;

import com.shiro.demo.shirojwt.dto.UserDto;
import com.shiro.demo.shirojwt.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class DbShiroRealm extends AuthorizingRealm {
	private final Logger log = LoggerFactory.getLogger(DbShiroRealm.class);
	
	private static final String encryptSalt = "F12839WhsnnEV$#23b";
	private UserService userService;
	
	public DbShiroRealm(UserService userService) {
		this.userService = userService;
		this.setCredentialsMatcher(new HashedCredentialsMatcher(Sha256Hash.ALGORITHM_NAME));
	}
	
	@Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken userpasswordToken = (UsernamePasswordToken)token;
		String username = userpasswordToken.getUsername();
		UserDto user = userService.getUserInfo(username);
		if(user == null)
			throw new AuthenticationException("用户名或者密码错误");
		
		return new SimpleAuthenticationInfo(user, user.getEncryptPwd(), ByteSource.Util.bytes(encryptSalt), "dbRealm");
	}


	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {      
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        UserDto user = (UserDto) principals.getPrimaryPrincipal();
        List<String> roles = user.getRoles();
        if(roles == null) {
            roles = userService.getUserRoles(user.getUserId());
            user.setRoles(roles);
        }
        if (roles != null)
            simpleAuthorizationInfo.addRoles(roles);

        return simpleAuthorizationInfo;
	}

	
}
