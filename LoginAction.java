package com.yaoba.app.web.m;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import me.chanjar.weixin.common.exception.WxErrorException;
import me.chanjar.weixin.cp.api.WxCpService;
import me.chanjar.weixin.mp.api.WxMpService;
import me.chanjar.weixin.mp.bean.result.WxMpOAuth2AccessToken;

import org.apache.commons.lang.StringUtils;
import org.apache.struts2.convention.annotation.Result;
import org.apache.struts2.convention.annotation.Results;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springside.modules.security.springsecurity.SpringSecurityUtils;
import org.springside.modules.utils.web.struts2.Struts2Utils;

import com.opensymphony.xwork2.ActionSupport;
import com.yaoba.app.entity.account.User;
import com.yaoba.app.entity.weixin.WeixinUser;
import com.yaoba.app.security.OperatorDetails;
import com.yaoba.app.service.account.UserManager;
import com.yaoba.app.service.system.ParameterManager;
import com.yaoba.app.service.weixin.WeixinMessageManager;
import com.yaoba.app.service.weixin.WeixinUserManager;
import com.yaoba.app.service.weixin.WxCpManager;
import com.yaoba.app.service.weixin.WxMpManager;
import com.yaoba.modules.utils.ServletUtils;
import com.yaoba.modules.utils.reflection.ConvertUtils;

@Results({ @Result(name = "teacher", location = "teacher.action", type = "redirect"), @Result(name = "student", location = "student.action", type = "redirect") })
public class LoginAction extends ActionSupport {

	/**
	 * 
	 */
	private static final long serialVersionUID = 7610882013139675389L;

	private UserDetailsService userDetailsService;
	private UserManager userManager;
	private WeixinMessageManager weixinMessageManager;
	private ParameterManager parameterManager;
	private WeixinUserManager weixinUserManager;
	private String loginName;
	private String password;

	private String redirectUrl;
	private String userId;

	private List<User> userList;

	@Override
	public String execute() throws Exception {

		HttpServletResponse response = Struts2Utils.getResponse();
		User user = userManager.getCurrentUser();

		if (StringUtils.isNotBlank(redirectUrl)) {
			redirectUrl = URLDecoder.decode(redirectUrl, "UTF-8");
		}

		// System.out.println("user:" + user);
		if (user == null) {
			// 如果未登录而且是在微信浏览器中打开，去后台验证是否有绑定用户
			if (ServletUtils.isWeixin(Struts2Utils.getRequest()) && StringUtils.isNotBlank(redirectUrl)) {
				String systemUrl = parameterManager.getParameterValue(ParameterManager.SYSTEM_URL);
				if (weixinMessageManager.isWxcp()) {
					WxCpService wxCpService = WxCpManager.getWxCpService();
					String oauth2Url = systemUrl + "m/login!cpOauth2.action?redirectUrl=" + URLEncoder.encode(redirectUrl, "UTF-8");
					String url = wxCpService.oauth2buildAuthorizationUrl(oauth2Url, "state");
					System.out.println("准备跳转:" + url);
					response.sendRedirect(url);
					return null;
				} else if (weixinMessageManager.isWxmp()) {
					WxMpService wxMpService = WxMpManager.getWxMpService();
					String oauth2Url = systemUrl + "m/login!mpOauth2.action?redirectUrl=" + URLEncoder.encode(redirectUrl, "utf-8");
					System.out.println("execute1");
					System.out.println(oauth2Url);
					String url = wxMpService.oauth2buildAuthorizationUrl(oauth2Url, "snsapi_base", "state");
					response.sendRedirect(url);
					return null;
				}
			}
			return SUCCESS;
		} else {
			if (StringUtils.isNotBlank(redirectUrl)) {
				if (StringUtils.isBlank(userId) || StringUtils.equals(user.getId(), userId)) {
					response.sendRedirect(redirectUrl);
					return null;
				} else {
					// 这里user.getId(), userId就不相等了，判断是否有在绑定的用户里
					if (containsWeixinUser(userId)) {
						saveUserDetails(userManager.get(userId).getLoginName());
						System.out.println("loginBindUser:" + redirectUrl);
						response.sendRedirect(redirectUrl);
						return null;
					} else {
						Struts2Utils.renderHtml("非法请求，请退出已登录的用户。");
						return null;
					}

				}
			} else {
				// 如果没有指定跳转地址，跳转到教师主页
				return StringUtils.lowerCase(userManager.getLoggedUser().getDtype());
			}
		}

	}

	public String login() {
		UserDetails userDetails;
		try {
			userDetails = userDetailsService.loadUserByUsername(loginName);
		} catch (Exception e) {
			addActionMessage("用户" + loginName + "不存在");
			return SUCCESS;
		}
		if (userDetails == null) {
		}
		if ("sha".equals(userManager.getPasswordEncoder())) {
			PasswordEncoder encoder = new ShaPasswordEncoder();
			if (!StringUtils.equals(encoder.encodePassword(password, null), userDetails.getPassword())) {
				addActionMessage("密码错误");
				return SUCCESS;
			}
		} else {
			if (!StringUtils.equals(password, userDetails.getPassword())) {
				addActionMessage("密码错误");
				return SUCCESS;
			}
		}

		SpringSecurityUtils.saveUserDetailsToContext(userDetails, Struts2Utils.getRequest());
		return StringUtils.lowerCase(userManager.getLoggedUser().getDtype());
	}

	public void mpOauth2() throws WxErrorException, IOException {
		System.out.println("oauth2");
		WxMpService wxMpService = WxMpManager.getWxMpService();

		HttpServletRequest request = Struts2Utils.getRequest();
		HttpServletResponse response = Struts2Utils.getResponse();

		String code = request.getParameter("code");
		WxMpOAuth2AccessToken token = wxMpService.oauth2getAccessToken(code);
		String weixinUserId = token.getOpenId();

		Struts2Utils.getSession().setAttribute(WeixinUserManager.WEIXIN_USER_ID, weixinUserId);
		System.out.println(weixinUserId);

		WeixinUser weixinUser = weixinUserManager.findUnique(Restrictions.eq("id", weixinUserId));
		if (weixinUser == null) {
			response.sendRedirect("./login.action");
			return;
		}
		List<User> userList = weixinUser.getUserList();
		System.out.println("userList-userList:" + ConvertUtils.convertElementPropertyToString(userList, "name", ","));
		System.out.println("redirectUrl:" + redirectUrl);

		// 保存微信对应的用户
		Struts2Utils.getSession().setAttribute(WeixinUserManager.WEIXIN_BINDING_USER_ID_LIST, ConvertUtils.convertElementPropertyToList(userList, "id"));

		System.out.println("保存session:" + ConvertUtils.convertElementPropertyToList(userList, "id"));

		for (User user : userList) {
			System.out.println(redirectUrl);
			System.out.println("userId=" + user.getId());
			if (StringUtils.contains(redirectUrl, "userId=" + user.getId())) {
				saveUserDetails(user.getLoginName());
				response.sendRedirect(redirectUrl);
				return;
			}
		}
		// 如果只有一个用户，直接跳转
		if (userList.size() == 1) {
			saveUserDetails(userList.get(0).getLoginName());
			response.sendRedirect(redirectUrl);
			return;
		} else if (userList.size() > 1) {
			// 选择要登录的用户
			response.sendRedirect("login!selectUser.action?redirectUrl=" + redirectUrl);
			return;
		}
		// 如果没有带userId最后再跳转
		response.sendRedirect(redirectUrl);
	}

	/**
	 * 选择登录用户页面
	 * 
	 * @return
	 * @throws IOException
	 */
	public String selectUser() throws Exception {

		List<String> userIdList = (List<String>) Struts2Utils.getSession().getAttribute(WeixinUserManager.WEIXIN_BINDING_USER_ID_LIST);

		System.out.println("取session:" + userIdList);
		if (userIdList == null) {
			// 如果没有绑定用户 跳到登录页面
			return SUCCESS;
		}
		System.out.println("userIdList:" + StringUtils.join(userIdList, ","));
		if (userIdList.size() == 1) {
			User user = userManager.get(userIdList.get(0));
			saveUserDetails(user.getLoginName());
			Struts2Utils.getResponse().sendRedirect(StringUtils.defaultIfEmpty(redirectUrl, "teacher.action"));
			return "";
		} else {
			userList = userManager.find(Restrictions.in("id", userIdList));
			System.out.println(ConvertUtils.convertElementPropertyToString(userList, "name", ","));
			redirectUrl = URLEncoder.encode(redirectUrl, "utf-8");
			return "selectUser";
		}
	}

	/**
	 * 登录选择的用户用户
	 * 
	 * @return
	 * @throws IOException
	 */
	@SuppressWarnings("unchecked")
	public void loginSelectUser() throws IOException {
		List<String> userIdList = (List<String>) Struts2Utils.getSession().getAttribute(WeixinUserManager.WEIXIN_BINDING_USER_ID_LIST);
		if (userIdList != null && userIdList.contains(userId)) {
			User user = userManager.get(userId);
			saveUserDetails(user.getLoginName());
			Struts2Utils.getResponse().sendRedirect(StringUtils.defaultIfEmpty(redirectUrl, "teacher.action"));
		}
	}

	/**
	 * 判断传过来的userId是否存在绑定的微信用户中（一个用户可以绑定多个用户）
	 * 
	 * @param userId
	 * @return
	 */
	private boolean containsWeixinUser(String userId) {

		List<String> userIdList = (List<String>) Struts2Utils.getSession().getAttribute(WeixinUserManager.WEIXIN_BINDING_USER_ID_LIST);
		if (userIdList != null && userIdList.contains(userId)) {
			return true;
		} else {
			return false;
		}
	}

	private void saveUserDetails(String loginName) {
		OperatorDetails userDetails = (OperatorDetails) userDetailsService.loadUserByUsername(loginName);
		SpringSecurityUtils.saveUserDetailsToContext(userDetails, Struts2Utils.getRequest());
	}

	public void setLoginName(String loginName) {
		this.loginName = loginName;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Autowired
	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Autowired
	public void setUserManager(UserManager userManager) {
		this.userManager = userManager;
	}

	@Autowired
	public void setWeixinMessageManager(WeixinMessageManager weixinMessageManager) {
		this.weixinMessageManager = weixinMessageManager;
	}

	@Autowired
	public void setParameterManager(ParameterManager parameterManager) {
		this.parameterManager = parameterManager;
	}

	@Autowired
	public void setWeixinUserManager(WeixinUserManager weixinUserManager) {
		this.weixinUserManager = weixinUserManager;
	}

	public String getRedirectUrl() {
		return redirectUrl;
	}

	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public List<User> getUserList() {
		return userList;
	}

}
