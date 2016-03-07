package shiroTest;


import java.util.Arrays;
import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;


public class TestShiro {
	
	public void testTwo(){
		this.testOne("classpath:shiro-realm.ini");
		
		Subject subject = SecurityUtils.getSubject();
		PrincipalCollection principalCollection = subject.getPrincipals();
		Assert.assertEquals(2, principalCollection.asList().size());
		List<String> list = Lists.newArrayList();
		list = principalCollection.asList();
		for(String str : list){
			LOG.info("身份信息:"+str);
		}
	}
	
	
	public void testOne(String configFile){
		LOG.info("------------------测试开始------------------");
		//获取securityManager工厂， 读取shiro.ini配置初始化
		Factory<SecurityManager> factory = new IniSecurityManagerFactory(configFile);
		
		//获取securityManager 并绑定给securityUtil
		SecurityManager securityManager = factory.getInstance();
		SecurityUtils.setSecurityManager(securityManager);
		
		//获取subject
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken("wang", "123");
		
		//验证登录
		try {
			LOG.info("开始登录:"+token.getUsername());
			subject.login(token);
			
		} catch (Exception e) {
			LOG.info("登录失败,用户名或密码错误");
		}
		
		Assert.assertEquals(true, subject.isAuthenticated());
		LOG.info("登录成功:"+token.getUsername());
		
		LOG.info("------------------测试结束------------------");
	}
	
	
	public void testRoles(){
		String configFile = "classpath:shiro.ini";
		String username = "zhang";
		String password = "123";
		this.login(configFile, username, password);
		
		Subject subject = SecurityUtils.getSubject();
		LOG.info("角色验证:role1");
		Assert.assertTrue(subject.hasRole("role1"));
		LOG.info("role1-->成功");
		LOG.info("角色验证:role1,role2");
		Assert.assertTrue(subject.hasAllRoles(Arrays.asList("role1", "role2")));
		LOG.info("role1,role2-->成功");
		LOG.info("角色验证:role1,role2,role3");
		Assert.assertTrue(subject.hasAllRoles(Arrays.asList("role1", "role2", "role3")));
		LOG.info("role1,role2,role3-->成功");
	}
	
	@Test
	public void testPermission(){
		String configFile = "classpath:shiro.ini";
		String username = "wang";
		String password = "123";
		
		this.login(configFile, username, password);
		
		Subject subject = SecurityUtils.getSubject();
		LOG.info("{}", subject.getPrincipal());
		
		LOG.info("验证权限:user:create");
		Assert.assertTrue(subject.isPermitted("user:create"));
		LOG.info("user:create-->成功");
		
		LOG.info("验证权限:user:update");
		Assert.assertTrue(subject.isPermitted("user:update"));
		LOG.info("user:update-->成功");
		
		LOG.info("check验证权限:user:delete");
		subject.checkPermission("user:delete");
		LOG.info("user:delete-->成功");
		
		LOG.info("验证权限:user:delete");
		Assert.assertTrue(subject.isPermitted("user:delete"));
		LOG.info("user:delete-->成功");
		
		
	}
	
	public void login(String configFile, String username, String password){
		Factory<SecurityManager> factory = new IniSecurityManagerFactory(configFile);
		SecurityManager securityManager = factory.getInstance();
		
		SecurityUtils.setSecurityManager(securityManager);
		Subject subject = SecurityUtils.getSubject();
		
		UsernamePasswordToken token = new UsernamePasswordToken(username, password);
		subject.login(token);
		
	}
	
	
	@After
    public void tearDown() throws Exception {
        ThreadContext.unbindSubject();//退出时请解除绑定Subject到线程 否则对下次测试造成影响
        LOG.info("退出时请解除绑定Subject到线程 否则对下次测试造成影响");
    }
	
	private static final transient Logger LOG = LoggerFactory.getLogger(TestShiro.class);
}
