/**********************************************************************************
 * $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-webapp/webapp/src/java/org/etudes/cdp/webapp/CdpServlet.java $
 * $Id: CdpServlet.java 12379 2015-12-23 23:42:59Z ggolden $
 ***********************************************************************************
 *
 * Copyright (c) 2011, 2012, 2013, 2014 Etudes, Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **********************************************************************************/

package org.etudes.cdp.webapp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.impl.dv.util.Base64;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.etudes.activitymeter.api.Overview;
import org.etudes.activitymeter.api.OverviewService;
import org.etudes.activitymeter.api.ParticipantOverview;
import org.etudes.activitymeter.api.ParticipantOverviewsSort;
import org.etudes.activitymeter.api.ParticipantStatus;
import org.etudes.api.app.jforum.AccessDates;
import org.etudes.api.app.jforum.Attachment;
import org.etudes.api.app.jforum.Category;
import org.etudes.api.app.jforum.Forum;
import org.etudes.api.app.jforum.Grade;
import org.etudes.api.app.jforum.JForumAccessException;
import org.etudes.api.app.jforum.JForumAttachmentBadExtensionException;
import org.etudes.api.app.jforum.JForumAttachmentOverQuotaException;
import org.etudes.api.app.jforum.JForumCategoryService;
import org.etudes.api.app.jforum.JForumForumService;
import org.etudes.api.app.jforum.JForumGradeService;
import org.etudes.api.app.jforum.JForumGradesModificationException;
import org.etudes.api.app.jforum.JForumItemNotFoundException;
import org.etudes.api.app.jforum.JForumPostService;
import org.etudes.api.app.jforum.JForumPrivateMessageService;
import org.etudes.api.app.jforum.JForumSpecialAccessService;
import org.etudes.api.app.jforum.JForumSynopticService;
import org.etudes.api.app.jforum.JForumUserService;
import org.etudes.api.app.jforum.Post;
import org.etudes.api.app.jforum.PrivateMessage;
import org.etudes.api.app.jforum.SpecialAccess;
import org.etudes.api.app.jforum.Topic;
import org.etudes.api.app.jforum.Topic.TopicType;
import org.etudes.api.app.melete.MeleteResourceService;
import org.etudes.api.app.melete.ModuleObjService;
import org.etudes.api.app.melete.ModuleService;
import org.etudes.api.app.melete.SectionObjService;
import org.etudes.api.app.melete.SectionResourceService;
import org.etudes.api.app.melete.SectionService;
import org.etudes.api.app.melete.ViewModBeanService;
import org.etudes.cdp.api.CdpHandler;
import org.etudes.cdp.api.CdpService;
import org.etudes.cdp.api.CdpStatus;
import org.etudes.cdp.util.CdpResponseHelper;
import org.etudes.coursemap.api.CourseMapItem;
import org.etudes.coursemap.api.CourseMapItemDisplayStatus;
import org.etudes.coursemap.api.CourseMapItemType;
import org.etudes.coursemap.api.CourseMapMap;
import org.etudes.coursemap.api.CourseMapService;
import org.etudes.mneme.api.Assessment;
import org.etudes.mneme.api.AssessmentPermissionException;
import org.etudes.mneme.api.AssessmentPolicyException;
import org.etudes.mneme.api.AssessmentService;
import org.etudes.mneme.api.Pool;
import org.etudes.mneme.api.PoolService;
import org.etudes.mneme.api.Submission;
import org.etudes.mneme.api.SubmissionService;
import org.etudes.util.DateHelper;
import org.etudes.util.HtmlHelper;
import org.sakaiproject.announcement.api.AnnouncementChannel;
import org.sakaiproject.announcement.api.AnnouncementMessage;
import org.sakaiproject.announcement.api.AnnouncementMessageEdit;
import org.sakaiproject.announcement.api.AnnouncementMessageHeaderEdit;
import org.sakaiproject.announcement.api.AnnouncementService;
import org.sakaiproject.api.app.syllabus.SyllabusAttachment;
import org.sakaiproject.api.app.syllabus.SyllabusData;
import org.sakaiproject.api.app.syllabus.SyllabusItem;
import org.sakaiproject.api.app.syllabus.SyllabusManager;
import org.sakaiproject.authz.api.AuthzGroupService;
import org.sakaiproject.authz.api.Member;
import org.sakaiproject.authz.api.SecurityAdvisor;
import org.sakaiproject.authz.api.SecurityService;
import org.sakaiproject.chat.api.ChatChannel;
import org.sakaiproject.chat.api.ChatMessage;
import org.sakaiproject.chat.api.ChatMessageEdit;
import org.sakaiproject.chat.api.ChatMessageHeaderEdit;
import org.sakaiproject.chat.api.ChatService;
import org.sakaiproject.component.api.ServerConfigurationService;
import org.sakaiproject.component.cover.ComponentManager;
import org.sakaiproject.content.api.ContentHostingService;
import org.sakaiproject.content.api.ContentResource;
import org.sakaiproject.email.api.EmailService;
import org.sakaiproject.entity.api.EntityManager;
import org.sakaiproject.entity.api.EntityPropertyNotDefinedException;
import org.sakaiproject.entity.api.EntityPropertyTypeException;
import org.sakaiproject.entity.api.Reference;
import org.sakaiproject.entity.api.ResourceProperties;
import org.sakaiproject.event.api.NotificationService;
import org.sakaiproject.event.api.UsageSession;
import org.sakaiproject.exception.IdUnusedException;
import org.sakaiproject.exception.InUseException;
import org.sakaiproject.exception.PermissionException;
import org.sakaiproject.exception.ServerOverloadException;
import org.sakaiproject.exception.TypeException;
import org.sakaiproject.message.api.Message;
import org.sakaiproject.presence.api.PresenceService;
import org.sakaiproject.site.api.Group;
import org.sakaiproject.site.api.PubDatesService;
import org.sakaiproject.site.api.Site;
import org.sakaiproject.site.api.SiteService;
import org.sakaiproject.site.api.SpecialAccessToolService;
import org.sakaiproject.site.api.ToolConfiguration;
import org.sakaiproject.thread_local.api.ThreadLocalManager;
import org.sakaiproject.time.api.Time;
import org.sakaiproject.time.api.TimeService;
import org.sakaiproject.tool.api.Session;
import org.sakaiproject.tool.api.SessionManager;
import org.sakaiproject.user.api.Authentication;
import org.sakaiproject.user.api.AuthenticationException;
import org.sakaiproject.user.api.AuthenticationManager;
import org.sakaiproject.user.api.AuthenticationMultipleException;
import org.sakaiproject.user.api.Evidence;
import org.sakaiproject.user.api.User;
import org.sakaiproject.user.api.UserDirectoryService;
import org.sakaiproject.user.api.UserNotDefinedException;
import org.sakaiproject.util.IdPwEvidence;
import org.sakaiproject.util.StringUtil;
//import org.etudes.search.api.FoundItem;
//import org.etudes.search.api.SearchItem;
//import org.etudes.search.api.SearchService;

/**
 * The CDP servlet ...<br />
 * request parameters are sent in a POST in "multipart/form-data" format<br />
 * request user credentials are sent in as using HTTP Basic Authentication<br />
 * response is sent as a JSON string<br />
 * response includes "cdp:status"
 */
@SuppressWarnings("serial")
public class CdpServlet extends HttpServlet
{
	/**
	 * CdpParticipantStatus captures a user's relationship to the site.
	 */
	enum CdpParticipantStatus
	{
		active(3), blocked(1), dropped(2), enrolled(0), inactive(4);

		private final int sortOrder;

		private CdpParticipantStatus(int sortOrder)
		{
			this.sortOrder = Integer.valueOf(sortOrder);
		}

		public Integer getSortValue()
		{
			return sortOrder;
		}
	}

	class SiteMember
	{
		String aim = null;
		String avatar = null;
		String displayName = null;
		String eid = null;
		String email = null;
		String facebook = null;
		String firstName = null;
		String googlePlus = null;
		String groupTitle = null;
		String hiddenEmail = null;
		String iid = null;
		boolean includeSig = false;
		String interests = null;
		String lastName = null;
		String linkedIn = null;
		String location = null;
		String msn = null;
		String occupation = null;

		String role = null;
		boolean showEmail = false;
		String sig = null;
		String skype = null;
		CdpParticipantStatus status;
		String twitter = null;
		String userId = null;
		String website = null;
		String yahoo = null;
	}

	/** The name of the cookie we use to keep sakai session. */
	public static final String SESSION_COOKIE = "JSESSIONID";

	/** The current CDP version. */
	protected static final int CUR_CDP_VERSION = 18;

	protected static boolean DELAY = false;

	/** The name of the system property that will be used when setting the value of the session cookie. */
	protected static final String SAKAI_SERVERID = "sakai.serverId";

	/** The chunk size used when streaming (100k). */
	protected static final int STREAM_BUFFER_SIZE = 102400;

	/** Our log. */
	private static Log M_log = LogFactory.getLog(CdpServlet.class);

	/** The data helper. */
	protected DataHelper dataHelper = null;

	/** Track user session / presence. */
	protected Tracker tracker = null;

	/**
	 * Shutdown the servlet.
	 */
	public void destroy()
	{
		if (this.tracker != null) this.tracker.destroy();

		JvmThreads.stopReporting();

		M_log.info("destroy()");
		super.destroy();
	}

	/**
	 * Access the Servlet's information display.
	 * 
	 * @return servlet information.
	 */
	public String getServletInfo()
	{
		return "CDP";
	}

	/**
	 * Initialize the servlet.
	 * 
	 * @param config
	 *        The servlet config.
	 * @throws ServletException
	 */
	public void init(ServletConfig config) throws ServletException
	{
		super.init(config);

		// TODO: not clustered
		this.tracker = new Tracker(false);

		this.dataHelper = new DataHelper();

		// if there is no cdp service, create and register one
		// Note: if we are reset in an active server, this service impl will continue to exist
		// Note: maybe move this impl to another webapp? -ggolden
		CdpService cdpService = (CdpService) ComponentManager.get(CdpService.class);
		if (cdpService == null)
		{
			cdpService = new CdpServiceImpl();
			ComponentManager.loadComponent(CdpService.class, cdpService);
			M_log.info("init() - new cdp service: " + cdpService);
		}
		else
		{
			M_log.info("init() - using existing cdp service: " + cdpService);
		}

		ComponentManager.whenAvailable(ServerConfigurationService.class, new Runnable()
		{
			public void run()
			{
				String frequency = StringUtil.trimToNull(serverConfigurationService().getString("JvmThreads.frequency"));
				String details = StringUtil.trimToNull(serverConfigurationService().getString("JvmThreads.details"));
				try
				{
					if (frequency != null)
					{
						int sleep = Integer.valueOf(frequency);
						JvmThreads.startReporting(sleep, "true".equals(details));
					}
				}
				catch (NumberFormatException e)
				{
					M_log.warn("init: invalid JvmThreads.frequency: " + frequency);
				}
			}
		});
	}

	/**
	 * Convert from the string format to a Date
	 * 
	 * @param value
	 *        The date string format.
	 * @return The Date.
	 */
	protected Date acceptDate(String value)
	{
		value = StringUtil.trimToNull(value);
		if (value == null) return null;

		// use the end-user's locale and time zone prefs
		Locale userLocal = /* Locale.US; */DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		DateFormat format = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, userLocal);
		format.setTimeZone(userZone);

		try
		{
			Date date = format.parse(value);

			// sanity check year - must be between 1000 and 9999 (matched mysql DATE and DATETIME types validation)
			Calendar cal = Calendar.getInstance();
			cal.setTime(date);
			int year = cal.get(Calendar.YEAR);
			if ((year < 1000) || (year > 9999)) throw new IllegalArgumentException();

			return date;
		}
		catch (ParseException e)
		{
			// if not as expected, complain
			throw new IllegalArgumentException();
		}
	}

	/**
	 * Replace any access references in src or href attributes of tags with cdp/doc references
	 * 
	 * @param text
	 * @return The converted text.
	 */
	protected String accessToCdpDoc(String text, boolean pub)
	{
		try
		{
			String access = "access";
			if (pub) access = "pub_access";

			StringBuffer buf = new StringBuffer();

			Pattern p = Pattern.compile("(src|href)=\"(.*?)\"", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
			Matcher m = p.matcher(text);
			while (m.find())
			{
				String url = m.group(2);

				// if the url is a non-relative server access url
				int pos = internallyHostedUrl(url);
				if (pos != -1)
				{
					url = url.substring(pos);
				}

				// if the url is an access url
				if (url.startsWith("/access/"))
				{
					if (!url.startsWith("/access/lticontact/")) url = "/cdp/doc/" + access + "/" + url.substring(8);
				}

				StringBuffer replacement = new StringBuffer();
				replacement.append(m.group(1));
				replacement.append("=\"");
				replacement.append(url);
				replacement.append("\"");

				m.appendReplacement(buf, Matcher.quoteReplacement(replacement.toString()));
			}

			m.appendTail(buf);

			return buf.toString();
		}
		catch (Exception e)
		{
			M_log.warn("accessToCdpDoc: " + e.toString() + "\n" + text + "\n");
			return text;
		}
	}

	/**
	 * @return The ActivityMeter's OverviewService, via the component manager.
	 */
	protected OverviewService activityMeterService()
	{
		return (OverviewService) ComponentManager.get(OverviewService.class);
	}

	/**
	 * Populate the return map with some basic user information.
	 * 
	 * @param userId
	 *        The user id.
	 */
	protected void addUserInfo(String userId, Map<String, Object> rv)
	{
		rv.put("internalUserId", userId);
		try
		{
			User user = userDirectoryService().getUser(userId);
			String email = user.getEmail();
			if (email != null) rv.put("email", email);
			String name = user.getDisplayName();
			if (name != null) rv.put("displayName", name);
		}
		catch (UserNotDefinedException e)
		{
		}
	}

	/**
	 * @return The AnnouncementService, via the component manager.
	 */
	protected AnnouncementService announcementService()
	{
		return (AnnouncementService) ComponentManager.get(AnnouncementService.class);
	}

	/**
	 * @return The AssessmentService, via the component manager.
	 */
	protected AssessmentService assessmentService()
	{
		return (AssessmentService) ComponentManager.get(AssessmentService.class);
	}

	/**
	 * Authenticate the user from the HTTP Basic Auth information in the request. If successful, return the internal user id, else return null.
	 * 
	 * @param req
	 *        The HTTP request.
	 * @param parameters
	 *        The request parameters.
	 * @return The internal user id string, if authenticated, or null if not.
	 * @throws UnsupportedEncodingException
	 */
	protected String authenticate(HttpServletRequest req, Map<String, Object> parameters) throws UnsupportedEncodingException
	{
		// if we have a session established, use it
		String userId = sessionManager().getCurrentSessionUserId();

		if (userId == null)
		{
			userId = authenticateBasic(req);
		}

		if (userId == null)
		{
			userId = authenticateFromForm(req, parameters);
		}

		return userId;
	}

	/**
	 * Authenticate the user from the HTTP Basic Auth information in the request. If successful, return the internal user id, else return null.
	 * 
	 * @param req
	 *        The HTTP request.
	 * @return The internal user id string, if authenticated, or null if not.
	 * @throws UnsupportedEncodingException
	 */
	protected String authenticateBasic(HttpServletRequest req) throws UnsupportedEncodingException
	{
		// get the (optional) header
		String authorizationHeader = req.getHeader("Authorization");
		if (authorizationHeader == null) return null;

		// only process "Basic"
		if (!authorizationHeader.startsWith("Basic ")) return null;

		// isolate the encoded values
		String encodedNameAndPassword = authorizationHeader.substring("Basic ".length());

		// decode
		byte[] decoded = Base64.decode(encodedNameAndPassword);
		String nameAndPassword = new String(decoded, "UTF-8");

		// split at the ":"
		int colonPos = nameAndPassword.indexOf(":");
		if (colonPos == -1) return null;

		String userName = nameAndPassword.substring(0, colonPos);
		String password = nameAndPassword.substring(colonPos + 1);

		if ((userName.length() == 0) || (password.length() == 0)) return null;

		try
		{
			Evidence e = new IdPwEvidence(userName, password);
			Authentication a = authenticationManager().authenticate(e);

			// return the user id
			return a.getUid();
		}
		catch (AuthenticationMultipleException ex)
		{
			// id / password not enough, need iid / institution / password
		}
		catch (AuthenticationException ex)
		{
			// no good
		}

		// not successfully authenticated
		return null;
	}

	/**
	 * Authenticate from "userid" and "password" form parameters
	 * 
	 * @param req
	 *        The HTTP request.
	 * @return The internal user id string, if authenticated, or null if not.
	 */
	protected String authenticateFromForm(HttpServletRequest req, Map<String, Object> parameters)
	{
		String userName = StringUtil.trimToNull((String) parameters.get("userid"));
		String password = StringUtil.trimToNull((String) parameters.get("password"));

		if ((userName == null) || (password == null)) return null;

		try
		{
			Evidence e = new IdPwEvidence(userName, password);
			Authentication a = authenticationManager().authenticate(e);

			// return the user id
			return a.getUid();
		}
		catch (AuthenticationMultipleException ex)
		{
			// id / password not enough, need iid / institution / password
		}
		catch (AuthenticationException ex)
		{
			// no good
		}

		// not successfully authenticated
		return null;
	}

	/**
	 * @return The AuthenticationManager, via the component manager.
	 */
	protected AuthenticationManager authenticationManager()
	{
		return (AuthenticationManager) ComponentManager.get(AuthenticationManager.class);
	}

	/**
	 * @return The AuthzGroupService, via the component manager.
	 */
	protected AuthzGroupService authzGroupService()
	{
		return (AuthzGroupService) ComponentManager.get(AuthzGroupService.class);
	}

	/**
	 * @return The ChatService, via the component manager.
	 */
	protected ChatService chatService()
	{
		return (ChatService) ComponentManager.get(ChatService.class);
	}

	/**
	 * Check the security for this user doing this function within this context.
	 * 
	 * @param userId
	 *        the user id.
	 * @param function
	 *        the function.
	 * @param context
	 *        The context.
	 * @param ref
	 *        The entity reference.
	 * @return true if the user has permission, false if not.
	 */
	protected boolean checkSecurity(String userId, String function, String context)
	{
		// check for super user
		if (securityService().isSuperUser(userId)) return true;

		// check for the user / function / context-as-site-authz
		// use the site ref for the security service (used to cache the security calls in the security service)
		String siteRef = siteService().siteReference(context);

		// form the azGroups for a context-as-implemented-by-site
		Collection<String> azGroups = new ArrayList<String>(2);
		azGroups.add(siteRef);
		azGroups.add("!site.helper");

		boolean rv = securityService().unlock(userId, function, siteRef, azGroups);
		return rv;
	}

	/**
	 * Check the versions from the request, and decide if the client is too old for this version of the server.
	 * 
	 * @param parameters
	 *        The request parameters.
	 * @return true if the client version can be used, false if it is too old
	 */
	protected boolean checkVersion(Map<String, Object> parameters)
	{
		// String inTouchVersion = (String) parameters.get("inTouch_version");
		// String inTouchBuild = (String) parameters.get("inTouch_build");
		String cdpVersion = (String) parameters.get("cdp_version");
		// int itvMajor = 0;
		// int itvMinor = 0;
		int cdpMajor = 0;
		// int itvBuild = 0;
		// if (inTouchVersion != null)
		// {
		// String parts[] = StringUtil.split(inTouchVersion, ".");
		// itvMajor = Integer.parseInt(parts[0]);
		// itvMinor = Integer.parseInt(parts[1]);
		// }
		if (cdpVersion != null)
		{
			cdpMajor = Integer.parseInt(cdpVersion);
		}
		// if (inTouchBuild != null)
		// {
		// itvBuild = Integer.parseInt(inTouchBuild);
		// }
		// M_log.warn("version " + itvMajor + "." + itvMinor + " build " + itvBuild + " cdp " + cdpMajor);

		// reject any CDP older than current
		boolean tooOld = (cdpMajor < CUR_CDP_VERSION);

		return !tooOld;
	}

	/**
	 * @return The ContentHostingService, via the component manager.
	 */
	protected ContentHostingService contentHostingService()
	{
		return (ContentHostingService) ComponentManager.get(ContentHostingService.class);
	}

	/**
	 * @return The CourseMapService, via the component manager.
	 */
	protected CourseMapService courseMapService()
	{
		return (CourseMapService) ComponentManager.get(CourseMapService.class);
	}

	/**
	 * Expand the official term suffix (F12) into a description like "Fall 2012".
	 * 
	 * @param suffix
	 *        the term suffix.
	 * @return The term description.
	 */
	protected String describeTerm(String suffix)
	{
		if ("DEV".equals(suffix)) return "Development";
		if (StringUtil.trimToNull(suffix) == null) return "Project";
		if (suffix.startsWith("W")) return "Winter 20" + suffix.substring(1, 3);
		if (suffix.startsWith("SP")) return "Spring 20" + suffix.substring(2, 4);
		if (suffix.startsWith("SU")) return "Summer 20" + suffix.substring(2, 4);
		if (suffix.startsWith("F")) return "Fall 20" + suffix.substring(1, 3);

		return suffix;
	}

	/**
	 * Dispatch the request based on the path
	 * 
	 * @param req
	 * @param res
	 * @param parameters
	 * @param path
	 * @throws ServletException
	 * @throws IOException
	 */
	protected void dispatch(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path) throws ServletException,
			IOException
	{
		String threadName = Thread.currentThread().getName();
		try
		{
			Thread.currentThread().setName(threadName + path);

			// all responses send a JSON map, 200 status response. The real response status is in the map in the "cdp:status" entry.
			Map<String, Object> responseMap = null;

			String[] pathComponents = path.split("/");

			String userAgent = req.getHeader("user-agent");

			if (pathComponents.length > 1)
			{
				// check for a prefixed request
				if (pathComponents[1].indexOf("_") != -1)
				{
					String[] prefixRequest = pathComponents[1].split("_");

					CdpService cdpService = (CdpService) ComponentManager.get(CdpService.class);
					if (cdpService != null)
					{
						// get the handler for the prefix
						CdpHandler handler = cdpService.getCdpHandler(prefixRequest[0]);
						if (handler != null)
						{
							// authenticate & track
							String authenticatedUserId = authenticate(req, parameters);
							String siteId = (String) parameters.get("siteId");
							if ((authenticatedUserId != null) && (siteId != null))
							{
								if (this.tracker.setupFakeSession(authenticatedUserId, siteId))
								{
									// track user session and site presence
									this.tracker.trackUser(authenticatedUserId, req.getRemoteAddr(), req.getHeader("user-agent"));
									this.tracker.trackSitePresence(authenticatedUserId, siteId);
								}
							}

							// handle it
							responseMap = handler.handle(req, res, parameters, prefixRequest[1], path, authenticatedUserId);
							if (responseMap == null) responseMap = dispatchError(req, res, parameters, path);
						}
						else
						{
							responseMap = dispatchError(req, res, parameters, path);
						}
					}
					else
					{
						responseMap = dispatchError(req, res, parameters, path);
					}
				}
				else
				{
					// handle non-prefixed request

					// TODO:
					if (pathComponents[1].equals("snoop"))
					{
						responseMap = dispatchSnoop(req, res, parameters, path);
					}
					else if (pathComponents[1].equals("authenticate"))
					{
						responseMap = dispatchAuthenticate(req, res, parameters, path);
					}
					else if (pathComponents[1].equals("authenticateUserSite"))
					{
						responseMap = dispatchAuthenticateUserSite(req, res, parameters, path);
					}

					// if no authenticated user, we reject all the following requests
					else
					{
						String authenticatedUserId = authenticate(req, parameters);
						if (authenticatedUserId == null)
						{
							responseMap = new HashMap<String, Object>();
							responseMap.put(CdpStatus.CDP_STATUS, CdpStatus.notLoggedIn.getId());
						}

						else if (pathComponents[1].equals("heartbeat"))
						{
							responseMap = dispatchHeartbeat(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("sites"))
						{
							responseMap = dispatchSites(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("announcements"))
						{
							responseMap = dispatchAnnouncements(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("courseMap"))
						{
							responseMap = dispatchCourseMap(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("module"))
						{
							responseMap = dispatchModule(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("activity"))
						{
							responseMap = dispatchActivity(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("chat"))
						{
							responseMap = dispatchChat(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("privateMessages"))
						{
							responseMap = dispatchPrivateMessages(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("message"))
						{
							responseMap = dispatchMessage(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("news"))
						{
							responseMap = dispatchNewsItem(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("forums"))
						{
							responseMap = dispatchForums(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("topics"))
						{
							responseMap = dispatchTopics(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("recentTopics"))
						{
							responseMap = dispatchRecentTopics(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("posts"))
						{
							responseMap = dispatchPosts(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("postBody"))
						{
							responseMap = dispatchPostBody(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("postBodyQuote"))
						{
							responseMap = dispatchPostBodyQuote(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("members"))
						{
							responseMap = dispatchMembers(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("logout"))
						{
							responseMap = dispatchLogout(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("editPost"))
						{
							responseMap = dispatchEditPost(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("replyPost"))
						{
							responseMap = dispatchReplyPost(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("newPost"))
						{
							responseMap = dispatchNewPost(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("newChat"))
						{
							responseMap = dispatchNewChat(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("newPrivateMessage"))
						{
							responseMap = dispatchNewPrivateMessage(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("replyPrivateMessage"))
						{
							responseMap = dispatchReplyPrivateMessage(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("newTopic"))
						{
							responseMap = dispatchNewTopic(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("newNewsItem"))
						{
							responseMap = dispatchNewNews(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("updatedNewsItem"))
						{
							responseMap = dispatchUpdatedNews(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("acceptSyllabus"))
						{
							responseMap = dispatchAcceptSyllabus(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("deletePrivateMessage"))
						{
							responseMap = dispatchDeletePrivateMessage(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("deletePost"))
						{
							responseMap = dispatchDeletePost(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("deleteNewsItem"))
						{
							responseMap = dispatchDeleteNews(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("deleteChat"))
						{
							responseMap = dispatchDeleteChat(req, res, parameters, path, authenticatedUserId);
						}

						// TODO: move these to apps
						else if (pathComponents[1].equals("assessments"))
						{
							responseMap = dispatchAssessments(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("presence"))
						{
							responseMap = dispatchPresence(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("pools"))
						{
							responseMap = dispatchPools(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("postAssessmentDates"))
						{
							responseMap = dispatchPostAssessmentDates(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("deleteAssessments"))
						{
							responseMap = dispatchDeleteAssessments(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("publishAssessments"))
						{
							responseMap = dispatchPublishAssessments(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("unpublishAssessments"))
						{
							responseMap = dispatchUnpublishAssessments(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("archiveAssessments"))
						{
							responseMap = dispatchArchiveAssessments(req, res, parameters, path, authenticatedUserId);
						}
						else if (pathComponents[1].equals("upload"))
						{
							responseMap = dispatchUpload(req, res, parameters, path, authenticatedUserId);
						}

						/*
						 * else if (pathComponents[1].equals("search")) { responseMap = dispatchSearch(req, res, parameters, path); }
						 */
						else
						{
							responseMap = dispatchError(req, res, parameters, path);
						}
					}
				}
			}
			else
			{
				responseMap = dispatchError(req, res, parameters, path);
			}

			// IE9 does not like "application/json"... but inTouch requires it!
			String contentType = "text/plain";
			if (userAgent.startsWith("inTouch")) contentType = "application/json";

			// send the JSON response
			String response = formatResponse(responseMap);
			res.setContentType(contentType);
			res.setCharacterEncoding("UTF-8");
			PrintWriter out = res.getWriter();
			out.print(response);
		}
		finally
		{
			Thread.currentThread().setName(threadName);
		}
	}

	protected Map<String, Object> dispatchAcceptSyllabus(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchModule - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// tell syllabus this user has accepted now
		syllabusManager().saveSyllabusAcceptance(siteId, userId);

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchActivity(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchActivity - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// security
		if (!activityMeterService().allowActivityAccess(siteId, userId))
		{
			M_log.warn("dispatchActivity - not permitted for site: " + siteId + " user: " + userId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// build up a map to return - the main map has a single "activity" object
		Map<String, Object> activityMap = new HashMap<String, Object>();
		rv.put("activity", activityMap);

		// the main map has an "items" entry - a list of maps for each item
		List<Map<String, Object>> itemsMap = new ArrayList<Map<String, Object>>();
		activityMap.put("items", itemsMap);

		// get an overview for the site - for a 1 week period.
		Integer period = Integer.valueOf(7);
		Overview overview = activityMeterService().getOverview(siteId, period);

		// compute the cutoff date for "recent"
		Calendar cutoff = Calendar.getInstance();
		cutoff.add(Calendar.DATE, -1 * period.intValue());
		Date cutoffDate = cutoff.getTime();

		// get the participant overviews
		List<ParticipantOverview> participantOverviews = activityMeterService().getParticipantOverviews(siteId, ParticipantOverviewsSort.status_a,
				true);

		if (overview.getNumNotVisitedInPeriod() != null) activityMap.put("notVisitedAlertCount", overview.getNumNotVisitedInPeriod().toString());

		// TODO: we need members to see who the instructors are - this should really be part of the overview...
		List<SiteMember> members = getMembers(siteId);

		// process each participant
		for (ParticipantOverview item : participantOverviews)
		{
			org.etudes.api.app.jforum.User u = jForumUserService().getBySakaiUserId(item.getId());
			String avatar = null;
			if (u != null)
			{
				avatar = u.getAvatar();
				if (avatar != null)
				{
					avatar = "/cdp/doc/avatar/" + avatar;
				}
			}

			Map<String, Object> itemMap = new HashMap<String, Object>();
			itemsMap.add(itemMap);

			itemMap.put("userId", item.getId());
			itemMap.put("name", item.getSortName());
			String iid = memberIid(members, item.getId());
			if (iid != null) itemMap.put("iid", iid);

			// combine the instructor and ta status to be "999" (i.e. "hat" in inTouch lingo)
			int statusValue = 999;
			if (item.getStatus() != null)
			{
				if ((item.getStatus() != ParticipantStatus.ta) && (item.getStatus() != ParticipantStatus.instructor)
						&& (item.getStatus() != ParticipantStatus.observer))
				{
					statusValue = item.getStatus().getSortValue();
				}
			}
			itemMap.put("status", formatInt(statusValue));

			if (item.getGroupTitle() != null) itemMap.put("section", item.getGroupTitle());
			itemMap.put("firstVisit", formatDateSecondsSince1970(item.getFirstVisitDate()));
			itemMap.put("lastVisit", formatDateSecondsSince1970(item.getLastVisitDate()));
			boolean notVisitedAlert = ((item.getLastVisitDate() == null) || (item.getLastVisitDate().before(cutoffDate)));
			itemMap.put("notVisitedAlert", formatBoolean(notVisitedAlert));
			itemMap.put("visits", formatInt(item.getNumVisits()));
			itemMap.put("syllabusAccepted", formatDateSecondsSince1970(item.getSyllabusDate()));
			itemMap.put("modules", formatInt(item.getNumMeleteViews()));
			itemMap.put("posts", formatInt(item.getNumJforumPosts()));
			itemMap.put("submissions", formatInt(item.getNumMnemeSubmissions()));
			if (avatar != null) itemMap.put("avatar", avatar);
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchAnnouncements(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String pat,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchAnnouncements - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// build up a map to return - the main map has a single "announcements" object
		List<Map<String, String>> announcementsMap = new ArrayList<Map<String, String>>();
		rv.put("announcements", announcementsMap);

		String channelId = announcementService().channelReference(siteId, SiteService.MAIN_CONTAINER);
		// AnnouncementChannel channel = announcementService().getAnnouncementChannel(channelId);

		// check for permission
		boolean editor = announcementService().allowEditChannel(channelId);
		try
		{
			@SuppressWarnings("unchecked")
			List<AnnouncementMessage> messageList = announcementService().getMessages(channelId, null, 0, false, true, false);
			for (AnnouncementMessage msg : messageList)
			{
				// unless this user has edit permission, skip non-viewable announcements (those not yet released)
				if (!editor)
				{
					if (!isAnnouncementViewable(msg)) continue;
				}

				// each announcement has a map with some attributes
				Map<String, String> messageMap = new HashMap<String, String>();
				announcementsMap.add(messageMap);

				loadNews(msg, messageMap, false, false);
			}
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchAnnouncements: " + e.toString());

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchArchiveAssessments(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchArchiveAssessments - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// check for permission
		if (!assessmentService().allowManageAssessments(siteId))
		{
			M_log.warn("dispatchArchiveAssessments: no permission: user: " + userId + " site:" + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the assessment ids parameters
		String aids = (String) parameters.get("assessmentIds");
		if (aids == null)
		{
			M_log.warn("dispatchArchiveAssessments - no assessmentIds parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// process assessments
		String[] split = StringUtil.split(aids, "\t");
		for (String aid : split)
		{
			Assessment a = assessmentService().getAssessment(aid);
			if (a != null)
			{
				try
				{
					a.setArchived(Boolean.TRUE);
					assessmentService().saveAssessment(a);
				}
				catch (AssessmentPermissionException e)
				{
				}
				catch (AssessmentPolicyException e)
				{
				}
			}
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchAssessments(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchAssessments - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// build up a map to return - the main map has a single "assessments" object
		List<Map<String, String>> assessmentsMap = new ArrayList<Map<String, String>>();
		rv.put("assessments", assessmentsMap);

		// check for permission
		if (!assessmentService().allowManageAssessments(siteId))
		{
			M_log.warn("dispatchAssessments: no permission: user: " + userId + " site:" + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// TODO: sort?
		List<Assessment> assessments = assessmentService().getContextAssessments(siteId, AssessmentService.AssessmentsSort.title_a, false);
		for (Assessment a : assessments)
		{
			Map<String, String> assessmentMap = new HashMap<String, String>();
			assessmentsMap.add(assessmentMap);

			loadAssessment(a, assessmentMap);
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	/**
	 * Authenticate from the request Basic Auth information, return an "id" parameter with the user's internal id if successful
	 * 
	 * @param req
	 * @param res
	 * @param parameters
	 * @param path
	 * @throws ServletException
	 * @throws IOException
	 */
	protected Map<String, Object> dispatchAuthenticate(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path)
			throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// reject old version clients
		if (!checkVersion(parameters))
		{
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.oldVersion.getId());
			return rv;
		}

		String userId = authenticate(req, parameters);

		if (userId != null)
		{
			// track user session
			if (this.tracker.setupFakeSession(userId, null))
			{
				this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			}

			addUserInfo(userId, rv);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());
		}

		else
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
		}

		return rv;
	}

	/**
	 * Authenticate from the request Basic Auth information, return an "id" parameter with the user's internal id if successful
	 * 
	 * @param req
	 * @param res
	 * @param parameters
	 * @param path
	 * @throws ServletException
	 * @throws IOException
	 */
	protected Map<String, Object> dispatchAuthenticateUserSite(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// reject old version clients
		if (!checkVersion(parameters))
		{
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.oldVersion.getId());
			return rv;
		}

		String userId = authenticate(req, parameters);

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// valid login
		addUserInfo(userId, rv);

		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		// check the userId against the parameter (parameter allowed be null)
		String userIdParameter = (String) parameters.get("userId");
		if ((userIdParameter != null) && (!userId.equals(userIdParameter)))
		{
			rv.put("resultCode", "0");
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			rv.put("resultCode", "1");
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// check if the user has access to the site
		if (!siteService().allowAccessSite(siteId))
		{
			rv.put("resultCode", "1");
			return rv;
		}

		// all is well
		rv.put("resultCode", "2");
		return rv;
	}

	protected Map<String, Object> dispatchChat(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchChat - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		String channelId = null;
		try
		{
			Site site = siteService().getSite(siteId);
			ToolConfiguration chatTool = site.getToolForCommonId("sakai.chat");
			if (chatTool != null)
			{
				channelId = StringUtil.trimToNull(chatTool.getConfig().getProperty("channel"));
				if (channelId == null)
				{
					channelId = chatService().channelReference(siteId, SiteService.MAIN_CONTAINER);
				}
			}
		}
		catch (IdUnusedException e)
		{
		}

		if (channelId == null)
		{
			M_log.warn("dispatchChat - no channelId");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
			this.tracker.trackChatPresence(userId, siteId, chatService().extractChannelId(channelId));
		}

		// build up a map to return - the main map has a single "chat" object
		List<Map<String, String>> chatMap = new ArrayList<Map<String, String>>();
		rv.put("chat", chatMap);

		// get last seen message id parameter (optional)
		String lastSeenMessageId = (String) parameters.get("lastSeenMessageId");

		// Note: until we can know if there have been any messages deleted or changes since the last message id was sent,
		// we cannot send an append package, but must instead send them all.
		lastSeenMessageId = null;

		// append boolean - if true, the messages should be appended, else they are the full set
		rv.put("append", formatBoolean(lastSeenMessageId != null));

		try
		{
			@SuppressWarnings("unchecked")
			List<ChatMessage> messageList = chatService().getMessages(channelId, null, 0, true, false, false);

			// send all if we have not seen any yet
			boolean sending = (lastSeenMessageId == null);

			for (ChatMessage msg : messageList)
			{
				if (sending)
				{
					// each announcement has a map with some attributes
					Map<String, String> messageMap = new HashMap<String, String>();
					chatMap.add(messageMap);

					messageMap.put("messageId", msg.getReference());
					messageMap.put("date", formatDateSecondsSince1970(msg.getChatHeader().getDate()));
					messageMap.put("from", msg.getChatHeader().getFrom().getDisplayName());
					messageMap.put("fromUserId", msg.getChatHeader().getFrom().getId());
					messageMap.put("body", msg.getBody());
				}

				// see if this one is the last one we have seen - if so, get ready to send the next
				else if (msg.getReference().equals(lastSeenMessageId))
				{
					sending = true;
				}
			}
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchHomeItems: " + e.toString());

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchCourseMap(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchCourseMap - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// security
		if (!courseMapService().allowGetMap(siteId, userId))
		{
			M_log.warn("dispatchCourseMap - not permitted for site: " + siteId + " user: " + userId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// optional user id parameter
		String forUserId = (String) parameters.get("forUserId");

		// build up a map to return - the main map has a single "courseMap" object
		Map<String, Object> mapMap = new HashMap<String, Object>();
		rv.put("courseMap", mapMap);

		// get the map
		CourseMapMap map = null;
		if (forUserId == null)
		{
			map = courseMapService().getMap(siteId, userId);
		}
		else
		{
			map = courseMapService().getUnfilteredMap(siteId, forUserId);
		}
		loadCourseMap(map, mapMap);

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchDeleteAssessments(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchDeleteAssessments - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// check for permission
		if (!assessmentService().allowManageAssessments(siteId))
		{
			M_log.warn("dispatchDeleteAssessments: no permission: user: " + userId + " site:" + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the assessment ids parameters
		String aids = (String) parameters.get("assessmentIds");
		if (aids == null)
		{
			M_log.warn("dispatchDeleteAssessments - no assessmentIds parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// process assessments
		String[] split = StringUtil.split(aids, "\t");
		for (String aid : split)
		{
			Assessment a = assessmentService().getAssessment(aid);
			if (a != null)
			{
				try
				{
					if (assessmentService().allowRemoveAssessment(a))
					{
						assessmentService().removeAssessment(a);
					}
				}
				catch (AssessmentPermissionException e)
				{
				}
				catch (AssessmentPolicyException e)
				{
				}
			}
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchDeleteChat(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchDeleteChat - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the message id parameter
		String messageRef = (String) parameters.get("messageId");
		if (messageRef == null)
		{
			M_log.warn("dispatchDeleteChat - no messageId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the chat
		ChatMessage currentMessage = null;
		Reference ref = entityManager().newReference(messageRef);
		try
		{
			currentMessage = (ChatMessage) chatService().getMessage(ref);
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchDeleteChat - message not found: " + messageRef);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchDeleteChat - permission: " + e.toString());

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		String channelId = null;
		try
		{
			Site site = siteService().getSite(siteId);
			ToolConfiguration chatTool = site.getToolForCommonId("sakai.chat");
			if (chatTool != null)
			{
				channelId = StringUtil.trimToNull(chatTool.getConfig().getProperty("channel"));
				if (channelId == null)
				{
					channelId = chatService().channelReference(siteId, SiteService.MAIN_CONTAINER);
				}
			}
		}
		catch (IdUnusedException e)
		{
		}

		if (channelId == null)
		{
			M_log.warn("dispatchChat - no channelId");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// delete
		try
		{
			ChatChannel channel = chatService().getChatChannel(channelId);
			channel.removeMessage(currentMessage.getId());
			// ChatMessageEdit message = channel.editChatMessage(currentMessage.getId());

			// channel.removeMessage(message);
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchDeleteChat: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchDeleteChat: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		/*
		 * catch (InUseException e) { rv.put("editLockAlert", formatBoolean(true)); }
		 */
		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchDeleteNews(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchDeleteNews - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the message id parameter
		String messageRef = (String) parameters.get("messageId");
		if (messageRef == null)
		{
			M_log.warn("dispatchDeleteNews - no messageId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the announcement
		AnnouncementMessage currentMessage = null;
		Reference ref = entityManager().newReference(messageRef);
		try
		{
			currentMessage = (AnnouncementMessage) announcementService().getMessage(ref);
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchDeleteNews - announcement not found: " + messageRef);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchDeleteNews - permission: " + e.toString());

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// delete
		try
		{
			String channelId = announcementService().channelReference(siteId, SiteService.MAIN_CONTAINER);
			AnnouncementChannel channel = announcementService().getAnnouncementChannel(channelId);
			AnnouncementMessageEdit message = channel.editAnnouncementMessage(currentMessage.getId());

			channel.removeMessage(message);
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchDeleteNews: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchDeleteNews: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (InUseException e)
		{
			rv.put("editLockAlert", formatBoolean(true));
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchDeletePost(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchDeletePost - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the post id parameter
		String postIdStr = (String) parameters.get("postId");
		if (postIdStr == null)
		{
			M_log.warn("dispatchDeletePost - no messageId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int postId = -1;
		try
		{
			postId = Integer.valueOf(postIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("postId - messageId not int: " + postIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		List<Integer> ids = new ArrayList<Integer>(1);
		ids.add(Integer.valueOf(postId));

		// secure for only site members
		if (!siteService().allowAccessSite(siteId))
		{
			M_log.warn("dispatchDeletePost - user: " + userId + " not permitted to site: " + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		try
		{
			jForumPostService().removePost(postId, userId);
		}
		catch (JForumItemNotFoundException e)
		{
			M_log.warn("dispatchDeletePost - JForumItemNotFoundException");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (JForumAccessException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}
		catch (JForumGradesModificationException e)
		{
			M_log.warn("dispatchDeletePost - JForumGradesModificationException");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchDeletePrivateMessage(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchDeletePrivateMessage - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the message id parameter
		String messageIdStr = (String) parameters.get("messageId");
		if (messageIdStr == null)
		{
			M_log.warn("dispatchDeletePrivateMessage - no messageId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int messageId = -1;
		try
		{
			messageId = Integer.valueOf(messageIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchDeletePrivateMessage - messageId not int: " + messageIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		List<Integer> ids = new ArrayList<Integer>(1);
		ids.add(Integer.valueOf(messageId));

		// secure for only site members
		if (!siteService().allowAccessSite(siteId))
		{
			M_log.warn("dispatchDeletePrivateMessage - user: " + userId + " not permitted to site: " + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		try
		{
			this.jForumPrivateMessageService().deleteMessage(siteId, userId, ids);
		}
		catch (JForumAccessException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	@SuppressWarnings("unchecked")
	protected void dispatchDoc(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException
	{
		// if we have a session established, use it
		String userId = sessionManager().getCurrentSessionUserId();

		if (userId == null)
		{
			userId = authenticateBasic(req);
		}

		String[] pathComponents = req.getPathInfo().split("/");
		boolean pub = (pathComponents.length > 2) && pathComponents[2].startsWith("pub_");

		if ((!pub) && (userId == null))
		{
			// res.sendError(HttpServletResponse.SC_BAD_REQUEST);
			res.setHeader("WWW-Authenticate", "Basic realm=\"Etudes\"");
			res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		// setup the current session for the request
		if (userId != null)
		{
			if (this.tracker.setupFakeSession(userId, null))
			{
				// track user session (TODO: and site presence?)
				this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			}
		}

		if (pathComponents.length > 2)
		{
			if (!pathComponents[1].equals("doc"))
			{
				res.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			}

			if (pathComponents[2].equals("announcement") || pathComponents[2].equals("pub_announcement"))
			{
				// form a reference to the message
				String refStr = "/" + StringUtil.unsplit(pathComponents, 3, pathComponents.length - 3, "/");
				Reference ref = entityManager().newReference(refStr);

				// get the announcement
				try
				{
					// for a pub, use an advisor, then later check that the announcement is marked for public access
					if (pub)
					{
						securityService().pushAdvisor(new SecurityAdvisor()
						{
							public SecurityAdvice isAllowed(String userId, String function, String reference)
							{
								return SecurityAdvice.ALLOWED;
							}
						});
					}

					Message message = announcementService().getMessage(ref);

					if (message == null)
					{
						M_log.warn("dispatchDoc - announcement not found: " + refStr);

						res.sendError(HttpServletResponse.SC_NOT_FOUND);
						return;
					}

					// for public view, the message must be public view
					if (pub
							&& (message.getProperties().getProperty(ResourceProperties.PROP_PUBVIEW) == null || (!message.getProperties()
									.getProperty(ResourceProperties.PROP_PUBVIEW).equals(Boolean.TRUE.toString()))))
					{
						M_log.warn("dispatchDoc - pub_announcement not public: " + refStr);

						res.sendError(HttpServletResponse.SC_NOT_FOUND);
						return;
					}

					String processedBody = accessToCdpDoc(message.getBody(), pub);

					PrintWriter out = res.getWriter();
					res.setContentType("text/html");
					out.println("<html><head>");
					out.println("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
					out.println("<script type=\"text/javascript\" src=\"/ckeditor/ckeditor/plugins/ckeditor_wiris/core/WIRISplugins.js?viewer=image\" defer=\"defer\"></script>");
					out.println("</head><body>");
					out.println(processedBody);

					// add attachments if any
					if (!message.getHeader().getAttachments().isEmpty())
					{
						out.println("<h4 style=\"font-size:1em;color:#555;margin:1em 1em .2em 0;\">Attachments</h4><ul>");
						for (Reference attachment : (List<Reference>) (message.getHeader().getAttachments()))
						{
							String url = attachment.getUrl();
							// switch to a cdp/doc from /access
							String link = accessToCdpDoc("<a href=\"" + url + "\" target=\"_blank\">", pub);
							String description = attachment.getProperties().getPropertyFormatted("DAV:displayname");
							out.print("<li>" + link + description + "</a></li>");
						}
						out.println("</ul>");
					}

					out.println("</body></html>");

					// TODO: mark as read by user, if we are doing announcement read tracking -ggolden
				}
				catch (IdUnusedException e)
				{
					M_log.warn("dispatchDoc - announcement not found: " + refStr);

					res.sendError(HttpServletResponse.SC_NOT_FOUND);
					return;
				}
				catch (PermissionException e)
				{
					M_log.warn("dispatchDoc - permission: " + e.toString());

					res.sendError(HttpServletResponse.SC_NOT_FOUND);
					return;
				}
				finally
				{
					if (pub)
					{
						securityService().popAdvisor();
					}
				}
			}

			else if (pathComponents[2].equals("message"))
			{
				String messageIdStr = StringUtil.unsplit(pathComponents, 3, pathComponents.length - 3, "/");
				if (messageIdStr == null)
				{
					M_log.warn("dispatchDoc - message id missing");

					res.sendError(HttpServletResponse.SC_BAD_REQUEST);
					return;
				}
				int messageId = -1;
				try
				{
					messageId = Integer.valueOf(messageIdStr);
				}
				catch (NumberFormatException e)
				{
					M_log.warn("dispatchDoc - message id not int: " + messageIdStr);

					res.sendError(HttpServletResponse.SC_BAD_REQUEST);
					return;
				}

				PrivateMessage msg = jForumPrivateMessageService().getPrivateMessage(messageId);
				if (msg == null)
				{
					M_log.warn("dispatchDoc - message not found: " + messageIdStr);

					res.sendError(HttpServletResponse.SC_NOT_FOUND);
					return;
				}

				// check security - the message must be to or from the current user
				if (!(userId.equals(msg.getFromUser().getSakaiUserId()) || userId.equals(msg.getToUser().getSakaiUserId())))
				{
					M_log.warn("dispatchDoc - PM security violation for message id: " + messageIdStr + " from user: " + userId);

					res.sendError(HttpServletResponse.SC_NOT_FOUND);
					return;
				}

				msg.getToUser().getSakaiUserId();

				PrintWriter out = res.getWriter();
				res.setContentType("text/html");
				String text = StringUtil.trimToZero(msg.getPost().getRawText());

				text = accessToCdpDoc(text, false);

				// render the [quote] syntax
				text = StringHtml.htmlFromQuote(text);

				// add a full document wrapper
				out.println("<html><head>");
				out.println("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
				out.println("<script type=\"text/javascript\" src=\"/ckeditor/ckeditor/plugins/ckeditor_wiris/core/WIRISplugins.js?viewer=image\" defer=\"defer\"></script>");
				out.println("</head><body>");
				out.println(text);
				List<Attachment> attachments = msg.getPost().getAttachments();
				if ((attachments != null) && (!attachments.isEmpty()))
				{
					out.println("<h4 style=\"font-size:1em;color:#555;margin:1em 1em .2em 0;\">Attachments</h4><ul>");
					for (Attachment attachment : attachments)
					{
						String url = "/cdp/doc/jfa/" + attachment.getId();
						// switch to a cdp/doc from /access
						String link = accessToCdpDoc("<a href=\"" + url + "\">", false);
						String description = attachment.getInfo().getRealFilename();
						out.print("<li>" + link + description + "</a></li>");
					}
					out.println("</ul>");
				}

				out.println("</body></html>");

				// mark as read
				jForumPrivateMessageService().markMessageRead(messageId, userId, new Date(), true);
			}

			else if (pathComponents[2].equals("avatar"))
			{
				// for now, forward to jforum's avatar handling
				String path = "/images/avatar/" + StringUtil.unsplit(pathComponents, 3, pathComponents.length - 3, "/");
				ServletContext context = getServletContext().getContext("/jforum-images");
				if (context != null)
				{
					RequestDispatcher dispatcher = context.getRequestDispatcher(path);
					dispatcher.forward(req, res);
				}
			}

			else if ((pathComponents[2].equals("syllabus")) || (pathComponents[2].equals("pub_syllabus")))
			{
				// /syllabus/<site id>
				String siteId = StringUtil.unsplit(pathComponents, 3, pathComponents.length - 3, "/");

				// secure for only site members
				if ((!pub) && (!siteService().allowAccessSite(siteId)))
				{
					M_log.warn("dispatchDoc - syllabus security denied for site: " + siteId + " user: " + userId);

					res.sendError(HttpServletResponse.SC_NOT_FOUND);
					return;
				}

				sendSyllabus(req, res, siteId, userId, pub);
			}

			else if (pathComponents[2].equals("section"))
			{
				// /section/<sectionId>
				String sectionIdStr = StringUtil.unsplit(pathComponents, 3, pathComponents.length - 3, "/");
				int sectionId = -1;
				try
				{
					sectionId = Integer.valueOf(sectionIdStr);
				}
				catch (NumberFormatException e)
				{
					M_log.warn("dispatch - sectionId not int: " + sectionIdStr);
					res.sendError(HttpServletResponse.SC_BAD_REQUEST);
					return;
				}

				// get the section
				SectionObjService section = sectionService().getSection(sectionId);
				if (section == null)
				{
					M_log.warn("dispatchSection - section not found: " + sectionId);
					res.sendError(HttpServletResponse.SC_BAD_REQUEST);
					return;
				}
				ModuleObjService module = section.getModule();

				// security check
				ViewModBeanService security = moduleService().getViewModBean(userId, module.getCoursemodule().getCourseId(),
						module.getModuleId().intValue());
				if (!security.isVisibleFlag())
				{
					M_log.warn("dispatchSection - section security denied for section: " + sectionId + " user: " + userId);
					res.sendError(HttpServletResponse.SC_NOT_FOUND);
					return;
				}

				String resourceId = null; // section.getSectionResource().getResource().getResourceId();
				SectionResourceService sr = section.getSectionResource();
				if (sr != null)
				{
					MeleteResourceService mrs = sr.getResource();
					if (mrs != null)
					{
						resourceId = mrs.getResourceId();
					}
				}

				sendContent(req, res, resourceId, false);

				// mark as read
				sectionService().insertSectionTrack(sectionId, userId);
			}

			else if (pathComponents[2].equals("access") || pathComponents[2].equals("pub_access"))
			{
				String resourceId = null;
				boolean secure = true;

				// [3] may be content
				if (pathComponents[3].equals("content"))
				{
					resourceId = "/" + StringUtil.unsplit(pathComponents, 4, pathComponents.length - 4, "/");
				}

				// [3]/[4] may be meleteDocs/content, mnemeDocs/content ... [7] is site id
				else if (pathComponents.length > 8)
				{
					// secure for only site members
					String siteId = pathComponents[7];
					if (!siteService().allowAccessSite(siteId))
					{
						M_log.warn("dispatchDoc - m*docs security denied for site: " + siteId + " user: " + userId);

						res.sendError(HttpServletResponse.SC_NOT_FOUND);
						return;
					}

					secure = false;
					resourceId = "/" + StringUtil.unsplit(pathComponents, 5, pathComponents.length - 5, "/");
				}

				else
				{
					M_log.warn("dispatchDoc - not recognized: " + req.getPathInfo());

					res.sendError(HttpServletResponse.SC_BAD_REQUEST);
					return;
				}

				sendContent(req, res, resourceId, secure);
			}

			else if (pathComponents[2].equals("jfa"))
			{
				// /jfa/<attachment id>
				String idStr = pathComponents[3];
				int id = -1;
				try
				{
					id = Integer.valueOf(idStr);
				}
				catch (NumberFormatException e)
				{
					M_log.warn("dispatchDoc - not recognized: " + req.getPathInfo());

					res.sendError(HttpServletResponse.SC_BAD_REQUEST);
					return;
				}

				// get the attachment
				Attachment attachment = jForumPrivateMessageService().getPrivateMessageAttachment(id);
				String contentType = attachment.getInfo().getMimetype();
				String filePath = attachment.getInfo().getPhysicalFilename();
				String fileRoot = serverConfigurationService().getString("etudes.jforum.attachments.store.dir");
				String fileName = fileRoot + "/" + filePath;
				int fileSize = (int) attachment.getInfo().getFilesize();

				// for text, we need to do some special handling
				if (contentType.startsWith("text/"))
				{
					// get the content as text
					byte[] fileBytes = readFile(fileName, fileSize);
					String contentText = new String(fileBytes, "UTF-8");
					sendTextContent(req, res, contentType, contentText);
				}

				// for non-text, just send it (stream it in chunks to avoid the elephant-in-snake problem)
				else
				{
					InputStream content = streamFile(fileName);
					if (content == null)
					{
						res.sendError(HttpServletResponse.SC_BAD_REQUEST);
					}

					sendBinaryContent(req, res, contentType, null, fileSize, content);
				}
			}

			else
			{
				M_log.warn("dispatchDoc - type not recognized: " + pathComponents[2]);
				res.sendError(HttpServletResponse.SC_BAD_REQUEST);
			}
		}
	}

	protected Map<String, Object> dispatchEditPost(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchEditPost - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the edit-post id parameter
		String editPostIdStr = (String) parameters.get("postId");
		if (editPostIdStr == null)
		{
			M_log.warn("dispatchEditPost - no postId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int editPostId = -1;
		try
		{
			editPostId = Integer.valueOf(editPostIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchEditPost - postId not int: " + editPostId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the subject parameter
		String subject = (String) parameters.get("subject");
		if (subject == null)
		{
			M_log.warn("dispatchEditPost - no subject parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the body parameter
		String body = (String) parameters.get("body");
		if (body == null)
		{
			M_log.warn("dispatchEditPost - no body parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchEditPost - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		// convert the body from plain text to html if desired
		if (plainText)
		{
			body = StringHtml.htmlFromPlain(body);
		}

		// get the existing post
		Post post = jForumPostService().getPost(editPostId);
		if (post == null)
		{
			M_log.warn("dispatchEditPost - post not found: " + editPostId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// update
		post.setSubject(subject);
		post.setText(body);

		// set this current user here, for access checks (will not change the post's owner)
		org.etudes.api.app.jforum.User jUser = jForumUserService().getBySakaiUserId(userId);
		post.setPostedBy(jUser);

		// save
		try
		{
			jForumPostService().modifyPost(post);
		}
		catch (JForumAccessException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}
		catch (JForumAttachmentOverQuotaException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (JForumAttachmentBadExtensionException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	/**
	 * Dispatch the error response
	 * 
	 * @param req
	 * @param res
	 * @param parameters
	 * @param path
	 * @return
	 * @throws ServletException
	 * @throws IOException
	 */
	protected Map<String, Object> dispatchError(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path)
			throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());

		return rv;
	}

	protected Map<String, Object> dispatchForums(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchForums - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the optional category id parameter
		String categoryIdStr = (String) parameters.get("categoryId");
		int categoryId = -1;
		if (categoryIdStr != null)
		{
			try
			{
				categoryId = Integer.valueOf(categoryIdStr);
			}
			catch (NumberFormatException e)
			{
				M_log.warn("dispatchForums - categoryId not int: " + categoryIdStr);

				// add status parameter
				rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
				return rv;
			}
		}

		// secure for only site members
		if (!siteService().allowAccessSite(siteId))
		{
			M_log.warn("dispatchForums - user: " + userId + " not permitted to site: " + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// build up a map to return - the main map has a single "forums" object
		// and a "categories" object
		List<Map<String, Object>> categoriesMap = new ArrayList<Map<String, Object>>();
		rv.put("categories", categoriesMap);

		// get categories
		// List<Category> categories = jForumCategoryService().getContextCategoriesForums(siteId);
		List<Category> categories = jForumCategoryService().getUserContextCategories(siteId, userId);
		for (Category c : categories)
		{
			// filter on category if requested
			if ((categoryIdStr != null) && (categoryId != c.getId())) continue;

			String cid = Integer.toString(c.getId());
			Map<String, Object> categoryMap = new HashMap<String, Object>();
			// will add to categoriesMap below, but only if we got a forum
			categoryMap.put("categoryId", cid);
			categoryMap.put("title", c.getTitle());
			if (c.getAccessDates().getOpenDate() != null) categoryMap.put("open", formatDateSecondsSince1970(c.getAccessDates().getOpenDate()));
			if (c.getAccessDates().getDueDate() != null) categoryMap.put("due", formatDateSecondsSince1970(c.getAccessDates().getDueDate()));
			if (c.getAccessDates().getAllowUntilDate() != null)
				categoryMap.put("allowUntil", formatDateSecondsSince1970(c.getAccessDates().getAllowUntilDate()));
			categoryMap.put("hideTillOpen", formatBoolean(c.getAccessDates().isHideUntilOpen()));
			categoryMap.put("published", "1");// TODO:
			categoryMap.put("graded", formatBoolean(c.isGradable()));
			if (c.getGrade() != null)
			{
				categoryMap.put("minPosts", Integer.toString(c.getGrade().getMinimumPosts()));
				categoryMap.put("points", formatFloat(c.getGrade().getPoints()));
			}
			categoryMap.put("lockOnDue", formatBoolean(false)); // TODO: remove in sync with inTouch
			categoryMap.put("pastDueLocked", formatBoolean(pastDueAndLocked(c.getAccessDates(), null, null)));
			boolean notYetOpen = notYetOpen(c.getAccessDates(), null, null);
			categoryMap.put("notYetOpen", formatBoolean(notYetOpen));
			if (c.getBlocked()) categoryMap.put("blocked", c.getBlockedByTitle());

			// until inTouch 2, if notYetOpen, and not an instructor, skip it
			if (notYetOpen)
			{
				boolean managePrivileges = checkSecurity(userId, "jforum.manage", siteId);
				if (!managePrivileges) continue;
			}

			// the forums
			List<Map<String, String>> forumsMap = new ArrayList<Map<String, String>>();
			categoryMap.put("forums", forumsMap);

			// get the forums
			List<Forum> forums = c.getForums();
			boolean hasAtLeastOneForum = false;
			for (Forum f : forums)
			{
				// skip if not "published" - set to deny access
				// if (f.getAccessType() == Forum.ACCESS_DENY) continue;

				// TODO: skip if not yet open?

				// TODO: what about groups?

				Map<String, String> forumMap = new HashMap<String, String>();
				if (loadForum(c, f, forumMap, userId, siteId))
				{
					forumsMap.add(forumMap);
				}

				// we got one
				hasAtLeastOneForum = true;
			}

			// use this category only if we have at least one forum
			if (hasAtLeastOneForum)
			{
				categoriesMap.add(categoryMap);
			}
		}

		try
		{
			Site site = siteService().getSite(siteId);
			ToolConfiguration chatTool = site.getToolForCommonId("sakai.chat");
			if (chatTool != null)
			{
				String channel = StringUtil.trimToNull(chatTool.getConfig().getProperty("channel"));
				if (channel != null)
				{
					// use the last part of the ref
					String[] parts = StringUtil.split(channel, "/");
					channel = parts[parts.length - 1];
					if (channel.equalsIgnoreCase("main")) channel = "Main";
				}
				else
				{
					channel = "Main";
				}

				// online
				@SuppressWarnings("rawtypes")
				List presence = presenceService().getPresence(chatTool.getId());

				rv.put("chatName", channel);
				rv.put("chatPresence", formatBoolean(!presence.isEmpty()));
			}
		}
		catch (IdUnusedException e)
		{
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchHeartbeat(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// assure that expired presence is being checked
		presenceService().checkPresenceForExpiration();

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchLogout(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, null))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
		}

		// TODO: ???

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	@SuppressWarnings("unchecked")
	protected Map<String, Object> dispatchMembers(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchMembers - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		this.tracker.setupFakeSession(userId, siteId);

		// track user session and site presence
		this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));

		// ETU-407 - was causing presence from the admin / helpdesk use of Roster
		// this.tracker.trackSitePresence(userId, siteId);

		// build up a map to return - the main map has a single "members" object
		List<Map<String, String>> membersMap = new ArrayList<Map<String, String>>();
		rv.put("members", membersMap);

		Map<String, String> memberMap = null;

		// get the site members
		List<SiteMember> mbrs = getMembers(siteId);

		// get site presence
		List<UsageSession> sitePresence = presenceService().getPresence(siteId + "-presence");

		// get site's chat presence
		List<UsageSession> chatPresence = null;
		try
		{
			Site site = siteService().getSite(siteId);
			ToolConfiguration chatTool = site.getToolForCommonId("sakai.chat");
			if (chatTool != null)
			{
				chatPresence = (List<UsageSession>) presenceService().getPresence(chatTool.getId());
			}
		}
		catch (IdUnusedException e)
		{
		}

		// lists to use to check special access definitions per member
		List<Assessment> assessments = assessmentService().getContextAssessments(siteId, AssessmentService.AssessmentsSort.title_a, Boolean.FALSE);
		List<ModuleObjService> modules = moduleService().getModules(siteId);
		List<SpecialAccess> discussions = jForumSpecialAccessService().getBySite(siteId);

		for (SiteMember m : mbrs)
		{
			memberMap = new HashMap<String, String>();
			membersMap.add(memberMap);
			memberMap.put("userId", m.userId);
			memberMap.put("displayName", m.displayName);
			if (m.iid != null) memberMap.put("iid", m.iid);
			memberMap.put("eid", m.eid);
			memberMap.put("role", m.role);
			if (m.status == null)
			{
				// must be a "hat" (instructor, ta)
				memberMap.put("status", formatInt(999));
			}
			else
			{
				memberMap.put("status", formatInt(m.status.getSortValue()));
			}

			// include email only if not blocked by user preferences.
			memberMap.put("showEmail", formatBoolean(m.showEmail));
			if (m.showEmail)
			{
				String email = StringUtil.trimToNull(m.email);
				if (email != null) memberMap.put("email", email);
			}

			if (m.avatar != null)
			{
				String avatarPath = "/cdp/doc/avatar/" + m.avatar;
				memberMap.put("avatar", avatarPath);
			}

			if (m.website != null) memberMap.put("website", m.website);
			if (m.msn != null) memberMap.put("msn", m.msn);
			if (m.yahoo != null) memberMap.put("yahoo", m.yahoo);
			if (m.facebook != null) memberMap.put("facebook", m.facebook);
			if (m.twitter != null) memberMap.put("twitter", m.twitter);
			if (m.occupation != null) memberMap.put("occupation", m.occupation);
			if (m.interests != null) memberMap.put("interests", m.interests);
			if (m.aim != null) memberMap.put("aim", m.aim);
			if (m.location != null) memberMap.put("location", m.location);
			if (m.googlePlus != null) memberMap.put("googlePlus", m.googlePlus);
			if (m.skype != null) memberMap.put("skype", m.skype);
			if (m.linkedIn != null) memberMap.put("linkedIn", m.linkedIn);

			if (m.groupTitle != null) memberMap.put("groupTitle", m.groupTitle);

			for (UsageSession s : sitePresence)
			{
				if (s.getUserId().equals(m.userId))
				{
					memberMap.put("online", formatBoolean(true));
					break;
				}
			}

			if (chatPresence != null)
			{
				for (UsageSession s : chatPresence)
				{
					if (s.getUserId().equals(m.userId))
					{
						memberMap.put("inChat", formatBoolean(true));
						break;
					}
				}
			}

			if (m.userId.equals(userId))
			{
				memberMap.put("isLoginUser", formatBoolean(true));
			}

			memberMap.put("specialAccess", formatBoolean(specialAccessToolService().userAccessSet(m.userId, assessments, modules, discussions)));
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchMessage(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchMessage - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the message id parameter
		String messageIdStr = (String) parameters.get("messageId");
		if (messageIdStr == null)
		{
			M_log.warn("dispatchMessage - no messageId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int messageId = 0;
		try
		{
			messageId = Integer.valueOf(messageIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchMessage - messageId not int: " + messageIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchMessage - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		PrivateMessage msg = jForumPrivateMessageService().getPrivateMessage(messageId);
		if (msg == null)
		{
			M_log.warn("dispatchMessage - message not found: " + messageIdStr);

			res.sendError(HttpServletResponse.SC_NOT_FOUND);
			return rv;
		}

		// check security - the message must be to or from the current user
		if (!(userId.equals(msg.getFromUser().getSakaiUserId()) || userId.equals(msg.getToUser().getSakaiUserId())))
		{
			M_log.warn("dispatchMessage - PM security violation for message id: " + messageIdStr + " from user: " + userId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// build up a map to return - the main map has a single "message" object
		Map<String, String> messageMap = new HashMap<String, String>();
		rv.put("message", messageMap);

		messageMap.put("subject", msg.getPost().getSubject());
		messageMap.put("messageId", Integer.toString(msg.getId()));
		messageMap.put("date", formatDateSecondsSince1970(msg.getPost().getTime()));
		messageMap.put("from", msg.getFromUser().getFirstName() + " " + msg.getFromUser().getLastName());
		messageMap.put("fromUserId", msg.getFromUser().getSakaiUserId());

		// Note: we include the body here, not the bodyPath
		// We will convert from html to plain text if requested.
		// [quote] format and BBCode is left intact, not rendered
		// this may be a fragment
		String body = StringUtil.trimToZero(msg.getPost().getRawText());
		if (plainText)
		{
			body = StringHtml.plainFromHtml(body);
		}
		messageMap.put("body", body);

		messageMap.put("unread", formatBoolean(msg.getType() == PrivateMessage.TYPE_NEW));
		messageMap.put("draft", formatBoolean(false));

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchModule(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchModule - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the module id parameter
		String moduleIdStr = (String) parameters.get("moduleId");
		if (moduleIdStr == null)
		{
			M_log.warn("dispatchModule - no moduleId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int moduleId = -1;
		try
		{
			moduleId = Integer.valueOf(moduleIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchModule - moduleId not int: " + moduleIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the module
		ModuleObjService module = moduleService().getModule(moduleId);
		if (module == null)
		{
			M_log.warn("dispatchModule - module not found: " + moduleId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// security check
		ViewModBeanService security = moduleService().getViewModBean(userId, module.getCoursemodule().getCourseId(), module.getModuleId().intValue());
		if (!security.isVisibleFlag())
		{
			M_log.warn("dispatchModule - module: " + moduleIdStr + " not available to user: " + userId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// build up a map to return - the main map has a single "module" object
		Map<String, Object> moduleMap = new HashMap<String, Object>();
		rv.put("module", moduleMap);

		loadModule(module, moduleMap, userId);

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchNewChat(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchNewChat - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		String channelId = null;
		try
		{
			Site site = siteService().getSite(siteId);
			ToolConfiguration chatTool = site.getToolForCommonId("sakai.chat");
			if (chatTool != null)
			{
				channelId = StringUtil.trimToNull(chatTool.getConfig().getProperty("channel"));
				if (channelId == null)
				{
					channelId = chatService().channelReference(siteId, SiteService.MAIN_CONTAINER);
				}
			}
		}
		catch (IdUnusedException e)
		{
		}

		if (channelId == null)
		{
			M_log.warn("dispatchNewChat - no channelId");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		User user = null;
		try
		{
			user = userDirectoryService().getUser(userId);
		}
		catch (UserNotDefinedException e)
		{
			M_log.warn("dispatchNewChat - no User object found for user id: " + userId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the body parameter
		String body = (String) parameters.get("body");
		if (body == null)
		{
			M_log.warn("dispatchNewChat - no body parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// post this to chat
		try
		{
			Time now = timeService().newTime();
			ChatChannel channel = chatService().getChatChannel(channelId);
			ChatMessageEdit message = channel.addChatMessage();
			message.setBody(body);
			ChatMessageHeaderEdit header = message.getChatHeaderEdit();
			header.setDate(now);
			header.setFrom(user);

			channel.commitMessage(message);
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchNewChat: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchNewChat: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchNewNews(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchNewNews - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		User user = null;
		try
		{
			user = userDirectoryService().getUser(userId);
		}
		catch (UserNotDefinedException e)
		{
			M_log.warn("dispatchNewNews - no User object found for user id: " + userId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the subject parameter
		String subject = (String) parameters.get("subject");
		if (subject == null)
		{
			M_log.warn("dispatchNewNews - no subject parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// limit subject to 100
		if (subject.length() > 100) subject = subject.substring(0, 100);

		// get the body parameter
		String body = (String) parameters.get("body");
		if (body == null)
		{
			M_log.warn("dispatchNewNews - no body parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get draft
		String draftStr = (String) parameters.get("draft");
		if (draftStr == null)
		{
			M_log.warn("dispatchNewNews - no draft parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean draft = (draftStr.equals("1"));

		// get priority
		String priorityStr = (String) parameters.get("priority");
		if (priorityStr == null)
		{
			M_log.warn("dispatchNewNews - no priority parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean priority = (priorityStr.equals("1"));

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchNewNews - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		// convert the body from plain text to html if desired
		if (plainText)
		{
			body = StringHtml.htmlFromPlain(body);
		}

		// post this to announcements
		try
		{
			Time now = timeService().newTime();
			String channelId = announcementService().channelReference(siteId, SiteService.MAIN_CONTAINER);
			AnnouncementChannel channel = announcementService().getAnnouncementChannel(channelId);
			AnnouncementMessageEdit message = channel.addAnnouncementMessage();
			message.setBody(body);
			AnnouncementMessageHeaderEdit header = message.getAnnouncementHeaderEdit();
			header.setDate(now);
			header.setDraft(draft);
			header.setFrom(user);
			header.setSubject(subject);

			int notificationPriority = NotificationService.NOTI_NONE;
			if (priority) notificationPriority = NotificationService.NOTI_REQUIRED;

			// TODO: until this is added to the API...
			if (!draft)
			{
				message.getPropertiesEdit().addProperty(AnnouncementService.RELEASE_DATE, now.toString());
			}
			message.getPropertiesEdit().addProperty(AnnouncementService.NOTIFICATION_LEVEL,
					((notificationPriority == NotificationService.NOTI_REQUIRED) ? "r" : "n"));

			channel.commitMessage(message, notificationPriority);
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchNewNews: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchNewNews: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchNewPost(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchNewPost - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the topic id parameter
		String topicIdStr = (String) parameters.get("topicId");
		if (topicIdStr == null)
		{
			M_log.warn("dispatchNewPost - no topicId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int topicId = -1;
		try
		{
			topicId = Integer.valueOf(topicIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchNewPost - topicId not int: " + topicIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the subject parameter
		String subject = (String) parameters.get("subject");
		if (subject == null)
		{
			M_log.warn("dispatchNewPost - no subject parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// limit subject to 100
		if (subject.length() > 100) subject = subject.substring(0, 100);

		// get the body parameter
		String body = (String) parameters.get("body");
		if (body == null)
		{
			M_log.warn("dispatchNewPost - no body parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchNewPost - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		// convert the body from plain text to html if desired
		if (plainText)
		{
			body = StringHtml.htmlFromPlain(body);
		}

		org.etudes.api.app.jforum.User jUser = jForumUserService().getBySakaiUserId(userId);

		Topic topic = jForumPostService().getTopic(topicId);

		Post newPost = jForumPostService().newPost();
		newPost.setPostedBy(jUser);
		newPost.setSubject(subject);
		newPost.setSmiliesEnabled(Boolean.TRUE);
		newPost.setText(body);
		topic.getPosts().add(newPost);

		try
		{
			jForumPostService().createTopicPost(topic);
		}
		catch (JForumAccessException e)
		{
			M_log.warn("dispatchNewPost: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchNewPrivateMessage(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the to user id parameter
		String toUserIds = (String) parameters.get("toUserIds");
		if (toUserIds == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no toUserIds parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		String[] toIds = StringUtil.split(toUserIds, "|");

		// get the subject parameter
		String subject = (String) parameters.get("subject");
		if (subject == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no subject parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// limit subject to 100
		if (subject.length() > 100) subject = subject.substring(0, 100);

		// get the body parameter
		String body = (String) parameters.get("body");
		if (body == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no body parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		// secure for only site members
		if (!siteService().allowAccessSite(siteId))
		{
			M_log.warn("dispatchNewPrivateMessage - user: " + userId + " not permitted to site: " + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// convert the body from plain text to html if desired
		if (plainText)
		{
			body = StringHtml.htmlFromPlain(body);
		}

		PrivateMessage pm = jForumPrivateMessageService().newPrivateMessage(userId, null);
		pm.setContext(siteId);

		Post post = pm.getPost();
		post.setSubject(subject);
		post.setText(body);
		post.setTime(new Date());
		post.setSmiliesEnabled(Boolean.TRUE);

		try
		{
			jForumPrivateMessageService().sendPrivateMessageWithAttachments(pm, Arrays.asList(toIds));
		}
		catch (JForumAccessException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}
		catch (JForumAttachmentOverQuotaException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (JForumAttachmentBadExtensionException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchNewsItem(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchNewsItem - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the message id parameter
		String messageId = (String) parameters.get("messageId");
		if (messageId == null)
		{
			M_log.warn("dispatchNewsItem - no messageId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchNewsItem - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		// form a reference to the message
		Reference ref = entityManager().newReference(messageId);

		// get the announcement
		try
		{
			AnnouncementMessage message = (AnnouncementMessage) announcementService().getMessage(ref);

			if (message == null)
			{
				M_log.warn("dispatchNewsItem - announcement not found: " + messageId);

				res.sendError(HttpServletResponse.SC_NOT_FOUND);
				return rv;
			}

			// build up a map to return - the main map has a single "message" object
			Map<String, String> messageMap = new HashMap<String, String>();
			rv.put("message", messageMap);

			loadNews(message, messageMap, true, plainText);

			// check if the item is being edited
			try
			{
				String channelId = announcementService().channelReference(siteId, SiteService.MAIN_CONTAINER);
				AnnouncementChannel channel = announcementService().getAnnouncementChannel(channelId);
				AnnouncementMessageEdit edit = channel.editAnnouncementMessage(message.getId());

				channel.cancelMessage(edit);
			}
			catch (InUseException e)
			{
				rv.put("editLockAlert", formatBoolean(true));
			}
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchNewsItem - announcement not found: " + messageId);

			res.sendError(HttpServletResponse.SC_NOT_FOUND);
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchNewsItem - permission: " + e.toString());

			res.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchNewTopic(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchNewTopic - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the forum id parameter
		String forumIdStr = (String) parameters.get("forumId");
		if (forumIdStr == null)
		{
			M_log.warn("dispatchNewTopic - no forumId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the subject parameter
		String subject = (String) parameters.get("subject");
		if (subject == null)
		{
			M_log.warn("dispatchNewTopic - no subject parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;

		}

		// limit subject to 100
		if (subject.length() > 100) subject = subject.substring(0, 100);

		// get the body parameter
		String body = (String) parameters.get("body");
		if (body == null)
		{
			M_log.warn("dispatchNewTopic - no body parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		int forumId = 0;
		try
		{
			forumId = Integer.valueOf(forumIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchNewTopic - forumId not int: " + forumIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchNewTopic - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		// convert the body from plain text to html if desired
		if (plainText)
		{
			body = StringHtml.htmlFromPlain(body);
		}

		org.etudes.api.app.jforum.User jUser = jForumUserService().getBySakaiUserId(userId);

		Topic newTopic = jForumPostService().newTopic();
		newTopic.setForumId(forumId);
		newTopic.setType(TopicType.NORMAL.getType());
		newTopic.setPostedBy(jUser);
		newTopic.setTitle(subject);

		Post newPost = jForumPostService().newPost();
		newPost.setPostedBy(jUser);
		newPost.setSubject(subject);
		newPost.setSmiliesEnabled(Boolean.TRUE);
		newPost.setText(body);
		newTopic.getPosts().add(newPost);

		try
		{
			jForumPostService().createTopic(newTopic);
		}
		catch (JForumAccessException e)
		{
			M_log.warn("dispatchNewTopic: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchPools(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchPools - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// build up a map to return - the main map has a single "pools" object
		List<Map<String, String>> poolsMap = new ArrayList<Map<String, String>>();
		rv.put("pools", poolsMap);

		// check for permission
		if (!assessmentService().allowManageAssessments(siteId))
		{
			M_log.warn("dispatchPools: no permission: user: " + userId + " site:" + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// // this.questionService.preCountContextQuestions(toolManager.getCurrentPlacement().getContext());

		List<Pool> pools = poolService().getPools(siteId);
		for (Pool p : pools)
		{
			Map<String, String> poolMap = new HashMap<String, String>();
			poolsMap.add(poolMap);

			loadPool(p, poolMap);
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchPostAssessmentDates(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchPostAssessmentDates - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// check for permission
		if (!assessmentService().allowManageAssessments(siteId))
		{
			M_log.warn("dispatchPostAssessmentDates: no permission: user: " + userId + " site:" + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the date parameters
		String openDates = (String) parameters.get("openDates");
		if (openDates == null)
		{
			M_log.warn("dispatchPostAssessmentDates - no openDates parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		String dueDates = (String) parameters.get("dueDates");
		if (dueDates == null)
		{
			M_log.warn("dispatchPostAssessmentDates - no dueDates parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		String allowDates = (String) parameters.get("allowDates");
		if (allowDates == null)
		{
			M_log.warn("dispatchPostAssessmentDates - no allowDates parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// modifying these assessments
		Map<String, Assessment> assessments = new HashMap<String, Assessment>();

		// process open dates
		String[] split = StringUtil.split(openDates, "\t");
		for (String s : split)
		{
			// id=date
			String[] pair = StringUtil.split(s, "=");
			String assessmentId = pair[0];
			Date date = null;
			if (pair.length > 1) date = acceptDate(pair[1]);

			Assessment a = assessments.get(assessmentId);
			if (a == null)
			{
				a = assessmentService().getAssessment(assessmentId);
				if (a != null)
				{
					assessments.put(assessmentId, a);
				}
			}

			if (a != null)
			{
				a.getDates().setOpenDate(date);
			}
		}

		// process due dates
		split = StringUtil.split(dueDates, "\t");
		for (String s : split)
		{
			// id=date
			String[] pair = StringUtil.split(s, "=");
			String assessmentId = pair[0];
			Date date = null;
			if (pair.length > 1) date = acceptDate(pair[1]);

			Assessment a = assessments.get(assessmentId);
			if (a == null)
			{
				a = assessmentService().getAssessment(assessmentId);
				if (a != null)
				{
					assessments.put(assessmentId, a);
				}
			}

			if (a != null)
			{
				a.getDates().setDueDate(date);
			}
		}

		// process allow dates
		split = StringUtil.split(allowDates, "\t");
		for (String s : split)
		{
			// id=date
			String[] pair = StringUtil.split(s, "=");
			String assessmentId = pair[0];
			Date date = null;
			if (pair.length > 1) date = acceptDate(pair[1]);

			Assessment a = assessments.get(assessmentId);
			if (a == null)
			{
				a = assessmentService().getAssessment(assessmentId);
				if (a != null)
				{
					assessments.put(assessmentId, a);
				}
			}

			if (a != null)
			{
				a.getDates().setAcceptUntilDate(date);
			}
		}

		// save
		for (String aid : assessments.keySet())
		{
			Assessment a = assessments.get(aid);
			try
			{
				assessmentService().saveAssessment(a);
			}
			catch (AssessmentPermissionException e)
			{
			}
			catch (AssessmentPolicyException e)
			{
			}
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchPostBody(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchPostBody - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the message id parameter
		String postIdStr = (String) parameters.get("postId");
		if (postIdStr == null)
		{
			M_log.warn("dispatchPostBody - no postId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int postId = -1;
		try
		{
			postId = Integer.valueOf(postIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchPostBody - postId not int: " + postIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		Post p = jForumPostService().getPost(postId);
		rv.put("body", StringHtml.plainFromHtml(accessToCdpDoc(StringUtil.trimToZero(p.getRawText()), false)));

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchPostBodyQuote(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchPostBodyQuote - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the message id parameter
		String postIdStr = (String) parameters.get("postId");
		if (postIdStr == null)
		{
			M_log.warn("dispatchPostBodyQuote - no postId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int postId = -1;
		try
		{
			postId = Integer.valueOf(postIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchPostBodyQuote - postId not int: " + postIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		Post p = jForumPostService().getPost(postId);

		StringBuilder body = new StringBuilder();
		body.append("[quote=");
		body.append(p.getPostedBy().getFirstName());
		body.append(" ");
		body.append(p.getPostedBy().getLastName());
		body.append("]");
		body.append(StringHtml.plainFromHtml(accessToCdpDoc(StringUtil.trimToZero(p.getRawText()), false)));
		body.append("[/quote]");
		rv.put("body", body.toString());

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchPosts(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchPosts - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the topic id parameter
		String topicIdStr = (String) parameters.get("topicId");
		if (topicIdStr == null)
		{
			M_log.warn("dispatchPosts - no topicId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int topicId = -1;
		try
		{
			topicId = Integer.valueOf(topicIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchPosts - topicId not int: " + topicIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// we need members to see who the instructors are - this should really be part of the post query somehow...
		List<SiteMember> members = getMembers(siteId);

		try
		{
			List<Post> posts = jForumPostService().getTopicPosts(topicId, 0, 0, userId);

			if (!posts.isEmpty())
			{
				Post p = posts.get(0);
				Topic t = p.getTopic();
				Forum f = t.getForum();
				Category c = f.getCategory();

				Map<String, String> forumMap = new HashMap<String, String>();
				rv.put("forum", forumMap);
				loadForum(c, f, forumMap, userId, siteId);

				Map<String, String> topicMap = new HashMap<String, String>();
				rv.put("topic", topicMap);
				loadTopic(c, f, t, topicMap, userId, siteId);
			}

			// build up a map to return - the main map has a "posts" object
			List<Map<String, String>> postsMap = new ArrayList<Map<String, String>>();
			rv.put("posts", postsMap);

			for (Post p : posts)
			{
				Map<String, String> messageMap = new HashMap<String, String>();
				postsMap.add(messageMap);
				loadPost(p, messageMap, isInstructor(members, p.getPostedBy().getSakaiUserId()));
			}
		}
		catch (JForumAccessException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// record this topic as read by the user
		jForumPostService().markTopicRead(topicId, userId, new Date(), true);

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	@SuppressWarnings("unchecked")
	protected Map<String, Object> dispatchPresence(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchPresence - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// build up a map to return - the main map has a single "presence" object
		List<Map<String, String>> presenceMap = new ArrayList<Map<String, String>>();
		rv.put("presence", presenceMap);

		// TODO: check for permission
		// if (false)
		// {
		// M_log.warn("dispatchAssessments: no permission: user: " + userId + " site:" + siteId);
		//
		// // add status parameter
		// rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
		// return rv;
		// }

		// get site presence
		List<UsageSession> sitePresence = presenceService().getPresence(siteId + "-presence");

		// get site's chat presence
		List<UsageSession> chatPresence = null;
		try
		{
			Site site = siteService().getSite(siteId);
			ToolConfiguration chatTool = site.getToolForCommonId("sakai.chat");
			if (chatTool != null)
			{
				chatPresence = (List<UsageSession>) presenceService().getPresence(chatTool.getId());
			}
		}
		catch (IdUnusedException e)
		{
		}

		// remove dups from site presence
		Set<String> sitePresenceUsers = new HashSet<String>();
		for (UsageSession s : sitePresence)
		{
			sitePresenceUsers.add(s.getUserId());
		}

		for (String presenceUserId : sitePresenceUsers)
		{
			boolean inChat = false;
			if (chatPresence != null)
			{
				for (UsageSession chats : chatPresence)
				{
					if (chats.getUserId().equals(presenceUserId))
					{
						inChat = true;
						break;
					}
				}
			}

			Map<String, String> userMap = new HashMap<String, String>();
			presenceMap.add(userMap);

			loadPresenceUser(presenceUserId, inChat, userMap);
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchPrivateMessages(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchPrivateMessages - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// build up a map to return - the main map has a single "announcements" object
		List<Map<String, String>> privateMessagesMap = new ArrayList<Map<String, String>>();
		rv.put("messages", privateMessagesMap);

		Map<String, String> messageMap = null;

		List<PrivateMessage> msgs = jForumPrivateMessageService().inbox(siteId, userId);
		for (PrivateMessage m : msgs)
		{
			messageMap = new HashMap<String, String>();
			privateMessagesMap.add(messageMap);
			messageMap.put("subject", m.getPost().getSubject());
			messageMap.put("messageId", Integer.toString(m.getId()));
			messageMap.put("date", formatDateSecondsSince1970(m.getPost().getTime()));
			messageMap.put("from", m.getFromUser().getFirstName() + " " + m.getFromUser().getLastName());
			messageMap.put("fromUserId", m.getFromUser().getSakaiUserId());
			// Note: just give the body path, not the body text
			messageMap.put("bodyPath", "/cdp/doc/message/" + m.getId());
			messageMap.put("unread", formatBoolean(m.getType() == PrivateMessage.TYPE_NEW));
			messageMap.put("replied", formatBoolean(m.isReplied()));
			messageMap.put("draft", formatBoolean(false));
			// TODO: priority ? m.getPriority() 0 for general, 1 for high
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchPublishAssessments(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchPublishAssessments - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// check for permission
		if (!assessmentService().allowManageAssessments(siteId))
		{
			M_log.warn("dispatchPublishAssessments: no permission: user: " + userId + " site:" + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the assessment ids parameters
		String aids = (String) parameters.get("assessmentIds");
		if (aids == null)
		{
			M_log.warn("dispatchPublishAssessments - no assessmentIds parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// process assessments
		String[] split = StringUtil.split(aids, "\t");
		for (String aid : split)
		{
			Assessment a = assessmentService().getAssessment(aid);
			if (a != null)
			{
				try
				{
					a.setPublished(Boolean.TRUE);
					assessmentService().saveAssessment(a);
				}
				catch (AssessmentPermissionException e)
				{
				}
				catch (AssessmentPolicyException e)
				{
				}
			}
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchRecentTopics(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchTopics - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// build up a map to return - the main map has a single "topics" object
		List<Map<String, String>> topicsMap = new ArrayList<Map<String, String>>();
		rv.put("topics", topicsMap);

		Map<String, String> topicMap = null;

		List<Topic> topics;
		try
		{
			topics = jForumPostService().getRecentTopics(siteId, 0, userId);
			for (Topic t : topics)
			{
				topicMap = new HashMap<String, String>();
				if (loadTopic(t.getForum().getCategory(), t.getForum(), t, topicMap, userId, siteId))
				{
					topicsMap.add(topicMap);
				}
			}
		}
		catch (JForumAccessException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchReplyPost(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchReplyPost - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the reply-to-post id parameter
		String replyToPostIdStr = (String) parameters.get("postId");
		if (replyToPostIdStr == null)
		{
			M_log.warn("dispatchReplyPost - no postId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		// int replyToPostId = -1;
		// try
		// {
		// replyToPostId = Integer.valueOf(replyToPostIdStr);
		// }
		// catch (NumberFormatException e)
		// {
		// M_log.warn("dispatchReplyPost - postId not int: " + replyToPostIdStr);
		//
		// // add status parameter
		// rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
		// return rv;
		// }

		// get the topic id parameter
		String topicIdStr = (String) parameters.get("topicId");
		if (topicIdStr == null)
		{
			M_log.warn("dispatchReplyPost - no topicId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int topicId = -1;
		try
		{
			topicId = Integer.valueOf(topicIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchReplyPost - topicId not int: " + topicIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the subject parameter
		String subject = (String) parameters.get("subject");
		if (subject == null)
		{
			M_log.warn("dispatchReplyPost - no subject parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// limit subject to 100
		if (subject.length() > 100) subject = subject.substring(0, 100);

		// get the body parameter
		String body = (String) parameters.get("body");
		if (body == null)
		{
			M_log.warn("dispatchReplyPost - no body parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;

		}

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchReplyPost - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		// convert the body from plain text to html if desired
		if (plainText)
		{
			body = StringHtml.htmlFromPlain(body);
		}

		org.etudes.api.app.jforum.User jUser = jForumUserService().getBySakaiUserId(userId);

		Topic topic = jForumPostService().getTopic(topicId);

		Post newPost = jForumPostService().newPost();
		newPost.setPostedBy(jUser);
		newPost.setSubject(subject);
		newPost.setSmiliesEnabled(Boolean.TRUE);
		newPost.setText(body);
		topic.getPosts().add(newPost);

		try
		{
			jForumPostService().createTopicPost(topic);
		}
		catch (JForumAccessException e)
		{
			M_log.warn("dispatchReplyPost: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchReplyPrivateMessage(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the reply-to-msg id parameter
		String replyToMsgIdStr = (String) parameters.get("messageId");
		if (replyToMsgIdStr == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no messageId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int replyToMsgId = -1;
		try
		{
			replyToMsgId = Integer.valueOf(replyToMsgIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchNewPrivateMessage - messageId not int: " + replyToMsgIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the subject parameter
		String subject = (String) parameters.get("subject");
		if (subject == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no subject parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// limit subject to 100
		if (subject.length() > 100) subject = subject.substring(0, 100);

		// get the body parameter
		String body = (String) parameters.get("body");
		if (body == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no body parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchNewPrivateMessage - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		// secure for only site members
		if (!siteService().allowAccessSite(siteId))
		{
			M_log.warn("dispatchNewPrivateMessage - user: " + userId + " not permitted to site: " + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// convert the body from plain text to html if desired
		if (plainText)
		{
			body = StringHtml.htmlFromPlain(body);
		}

		PrivateMessage pm = jForumPrivateMessageService().newPrivateMessage(replyToMsgId);
		pm.setContext(siteId);

		Post post = pm.getPost();
		post.setSubject(subject);
		post.setText(body);
		post.setTime(new Date());
		post.setSmiliesEnabled(Boolean.TRUE);

		try
		{
			jForumPrivateMessageService().replyPrivateMessage(pm);
		}
		catch (JForumAccessException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}
		catch (JForumAttachmentOverQuotaException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (JForumAttachmentBadExtensionException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchSites(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, null))
		{
			// track user session
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
		}

		// Note: inTouch (1) does not send "all" or "status" parameters - wants published only (i.e. not all) and status! E3 (etudes.js userSites) always sends "all"=1, sometimes sets status. -ggolden

		// get the all (include published and unpublished)
		String all = (String) parameters.get("all");
		boolean filterOutUnpublished = !"1".equals(all);

		String status = (String) parameters.get("status");
		boolean includeStatus = "1".equals(status);
		boolean includeTools = false;

		String statusLimitStr = (String) parameters.get("statusLimit");
		int statusLimit = 0;
		if (statusLimitStr != null)
		{
			statusLimit = Integer.parseInt(statusLimitStr);
		}

		// special code to support inTouch (1)
		boolean intouchSiteFormat = false;
		if (all == null)
		{
			includeStatus = true;
			intouchSiteFormat = true;
		}

		// collect the user's sites
		List<Site> visibleSites = new ArrayList<Site>();
		List<Site> hiddenSites = new ArrayList<Site>();
		siteService().getOrderedSites(userId, visibleSites, hiddenSites);

		Map<String, Integer> unreadPmCounts = null;
		if (includeStatus && (!intouchSiteFormat))
		{
			// get the user's unread PM counts from all sites
			unreadPmCounts = this.dataHelper.getUserUnreadPmCounts(userId);
		}

		// build up a map to return - the main map has a single "sites" object
		List<Map<String, Object>> sitesMap = new ArrayList<Map<String, Object>>();
		rv.put("sites", sitesMap);

		// the visible sites
		int sitesProcessed = 0;
		for (Site site : visibleSites)
		{
			boolean includeStatusHere = includeStatus;
			if (statusLimit > 0)
			{
				if (sitesProcessed >= statusLimit)
				{
					includeStatusHere = false;
				}
			}

			if (filterOutUnpublished && !site.isPublished()) continue;

			// each site has a map with "siteId" and "title" strings
			Map<String, Object> siteMap = new HashMap<String, Object>();
			sitesMap.add(siteMap);
			loadSite(site, siteMap, true, userId, includeStatusHere, includeTools, unreadPmCounts, intouchSiteFormat);

			sitesProcessed++;
		}

		// the hidden sites (we never need status for these [except for the intouchSiteFormat, which wants status for all sites])
		for (Site site : hiddenSites)
		{
			if (filterOutUnpublished && !site.isPublished()) continue;

			// each site has a map with "siteId" and "title" strings
			Map<String, Object> siteMap = new HashMap<String, Object>();
			sitesMap.add(siteMap);
			loadSite(site, siteMap, false, userId, (intouchSiteFormat ? true : false), includeTools, unreadPmCounts, intouchSiteFormat);
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchSnoop(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path)
			throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// start with the request parameters
		rv.putAll(parameters);

		// and some information about the request
		rv.put("cdp:path", path);

		// and some auth info
		String userId = authenticate(req, parameters);
		if (userId != null)
		{
			rv.put("cdp:userId", userId);
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		// sleep
		try
		{
			Thread.sleep(5000);
		}
		catch (Exception ignore)
		{
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	/*
	 * protected Map<String, Object> dispatchSearch(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path) throws ServletException, IOException { Map<String, Object> rv = new HashMap<String, Object>();
	 * 
	 * // authenticate String userId = authenticate(req, parameters);
	 * 
	 * // in case that fails if (userId == null) { // add status parameter rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId()); return rv; }
	 * 
	 * // setup the current session for the request if (this.tracker.setupFakeSession(userId, null)) { // track user session this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent")); }
	 * 
	 * // get the search siteId parameter (optional) String searchSiteId = StringUtil.trimToNull((String) parameters.get("siteId"));
	 * 
	 * // get the toolId parameter (optional) String toolId = StringUtil.trimToNull((String) parameters.get("toolId"));
	 * 
	 * // get the query parameter (optional) String query = StringUtil.trimToNull((String) parameters.get("query"));
	 * 
	 * // build up a map to return - the main map has a single "results" object List<Map<String, String>> resultsMap = new ArrayList<Map<String, String>>(); rv.put("results", resultsMap);
	 * 
	 * // perform the search List<FoundItem> results = this.searchService().search(searchSiteId, toolId, query);
	 * 
	 * for (FoundItem item : results) { Map<String, String> itemMap = new HashMap<String, String>(); resultsMap.add(itemMap); itemMap.put("itemId", item.getSearchItem().getId()); itemMap.put("title", item.getTitle()); }
	 * 
	 * // add status parameter rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());
	 * 
	 * return rv; }
	 */

	protected Map<String, Object> dispatchTopics(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchTopics - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// get the forum id parameter
		String forumIdStr = (String) parameters.get("forumId");
		if (forumIdStr == null)
		{
			M_log.warn("dispatchTopics - no forumId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		int forumId = 0;
		try
		{
			forumId = Integer.valueOf(forumIdStr);
		}
		catch (NumberFormatException e)
		{
			M_log.warn("dispatchTopics - forumId not int: " + forumIdStr);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// build up a map to return - the main map has a "topics" object
		List<Map<String, String>> topicsMap = new ArrayList<Map<String, String>>();
		rv.put("topics", topicsMap);

		// we also return an updated form
		Map<String, String> forumMap = new HashMap<String, String>();
		rv.put("forum", forumMap);

		Map<String, String> topicMap = null;

		try
		{
			List<Topic> topics = jForumPostService().getTopics(forumId, 0, 0, userId);

			// the forum
			Forum f = null;
			if (!topics.isEmpty())
			{
				Topic t = topics.get(0);
				f = t.getForum();
			}

			else
			{
				f = jForumForumService().getForum(forumId, userId);
			}
			Category c = f.getCategory();
			loadForum(c, f, forumMap, userId, siteId);

			for (Topic t : topics)
			{
				topicMap = new HashMap<String, String>();
				if (loadTopic(t.getForum().getCategory(), t.getForum(), t, topicMap, userId, siteId))
				{
					topicsMap.add(topicMap);
				}
			}
		}
		catch (JForumAccessException e)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchUnpublishAssessments(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters,
			String path, String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchUnpublishAssessments - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		// check for permission
		if (!assessmentService().allowManageAssessments(siteId))
		{
			M_log.warn("dispatchUnpublishAssessments: no permission: user: " + userId + " site:" + siteId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the assessment ids parameters
		String aids = (String) parameters.get("assessmentIds");
		if (aids == null)
		{
			M_log.warn("dispatchUnpublishAssessments - no assessmentIds parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// process assessments
		String[] split = StringUtil.split(aids, "\t");
		for (String aid : split)
		{
			Assessment a = assessmentService().getAssessment(aid);
			if (a != null)
			{
				try
				{
					a.setPublished(Boolean.FALSE);
					assessmentService().saveAssessment(a);
				}
				catch (AssessmentPermissionException e)
				{
				}
				catch (AssessmentPolicyException e)
				{
				}
			}
		}

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchUpdatedNews(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the site id parameter
		String siteId = (String) parameters.get("siteId");
		if (siteId == null)
		{
			M_log.warn("dispatchUpdatedNews - no siteId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, siteId))
		{
			// track user session and site presence
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
			this.tracker.trackSitePresence(userId, siteId);
		}

		User user = null;
		try
		{
			user = userDirectoryService().getUser(userId);
		}
		catch (UserNotDefinedException e)
		{
			M_log.warn("dispatchUpdatedNews - no User object found for user id: " + userId);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// get the message id parameter
		String messageRef = (String) parameters.get("messageId");
		if (messageRef == null)
		{
			M_log.warn("dispatchUpdatedNews - no messageId parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the subject parameter
		String subject = (String) parameters.get("subject");
		if (subject == null)
		{
			M_log.warn("dispatchUpdatedNews - no subject parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// limit subject to 100
		if (subject.length() > 100) subject = subject.substring(0, 100);

		// get the body parameter
		String body = (String) parameters.get("body");
		if (body == null)
		{
			M_log.warn("dispatchUpdatedNews - no body parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get draft
		String draftStr = (String) parameters.get("draft");
		if (draftStr == null)
		{
			M_log.warn("dispatchUpdatedNews - no draft parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean draft = (draftStr.equals("1"));

		// get priority
		String priorityStr = (String) parameters.get("priority");
		if (priorityStr == null)
		{
			M_log.warn("dispatchUpdatedNews - no priority parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean priority = (priorityStr.equals("1"));

		// get the announcement
		AnnouncementMessage currentMessage = null;
		Reference ref = entityManager().newReference(messageRef);
		try
		{
			currentMessage = (AnnouncementMessage) announcementService().getMessage(ref);
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchUpdatedNews - announcement not found: " + messageRef);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchUpdatedNews - permission: " + e.toString());

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get plainText
		String plainTextStr = (String) parameters.get("plainText");
		if (plainTextStr == null)
		{
			M_log.warn("dispatchNewNews - no plainText parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		boolean plainText = (plainTextStr.equals("1"));

		// convert the body from plain text to html if desired
		if (plainText)
		{
			body = StringHtml.htmlFromPlain(body);
		}

		// update this announcement
		try
		{
			Time now = timeService().newTime();
			String channelId = announcementService().channelReference(siteId, SiteService.MAIN_CONTAINER);
			AnnouncementChannel channel = announcementService().getAnnouncementChannel(channelId);
			AnnouncementMessageEdit message = channel.editAnnouncementMessage(currentMessage.getId());

			message.setBody(body);
			AnnouncementMessageHeaderEdit header = message.getAnnouncementHeaderEdit();
			header.setDate(now);
			header.setDraft(draft);
			header.setFrom(user);
			header.setSubject(subject);

			int notificationPriority = NotificationService.NOTI_NONE;
			if (priority) notificationPriority = NotificationService.NOTI_REQUIRED;

			// TODO: until this is added to the API...
			if (!draft)
			{
				message.getPropertiesEdit().addProperty(AnnouncementService.RELEASE_DATE, now.toString());
			}
			message.getPropertiesEdit().addProperty(AnnouncementService.NOTIFICATION_LEVEL,
					((notificationPriority == NotificationService.NOTI_REQUIRED) ? "r" : "n"));

			channel.commitMessage(message, notificationPriority);
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchUpdatedNews: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchUpdatedNews: exception: " + e);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (InUseException e)
		{
			rv.put("editLockAlert", formatBoolean(true));
		}

		// get the message to return the update
		currentMessage = null;
		try
		{
			currentMessage = (AnnouncementMessage) announcementService().getMessage(ref);
		}
		catch (IdUnusedException e)
		{
			M_log.warn("dispatchUpdatedNews - announcement not found (after update): " + messageRef);

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}
		catch (PermissionException e)
		{
			M_log.warn("dispatchUpdatedNews - permission (after update): " + e.toString());

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		Map<String, String> messageMap = new HashMap<String, String>();
		rv.put("update", messageMap);
		loadNews(currentMessage, messageMap, false, false);

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	protected Map<String, Object> dispatchUpload(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String path,
			String userId) throws ServletException, IOException
	{
		Map<String, Object> rv = new HashMap<String, Object>();

		// in case that fails
		if (userId == null)
		{
			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.accessDenied.getId());
			return rv;
		}

		// setup the current session for the request
		if (this.tracker.setupFakeSession(userId, null))
		{
			// track user session
			this.tracker.trackUser(userId, req.getRemoteAddr(), req.getHeader("user-agent"));
		}

		// get the destination path
		String destination = (String) parameters.get("destination");
		if (destination == null)
		{
			M_log.warn("dispatchUpload - no destination parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// get the file
		FileItem file = (FileItem) parameters.get("file");
		if (file == null)
		{
			M_log.warn("dispatchUpload - no file parameter");

			// add status parameter
			rv.put(CdpStatus.CDP_STATUS, CdpStatus.badRequest.getId());
			return rv;
		}

		// TODO: save it!

		// add status parameter
		rv.put(CdpStatus.CDP_STATUS, CdpStatus.success.getId());

		return rv;
	}

	/**
	 * Respond to requests.
	 * 
	 * @param req
	 *        The servlet request.
	 * @param res
	 *        The servlet response.
	 * @throws ServletException.
	 * @throws IOException.
	 */
	protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException
	{
		establishSessionFromCookie(req, res);

		// delay
		if (DELAY)
		{
			try
			{
				Thread.sleep(4 * 1000);
			}
			catch (Exception ignore)
			{
			}
		}

		// Note: we might want to break this out to another webapp... /docs or something
		try
		{
			dispatchDoc(req, res);
		}
		catch (Exception e)
		{
			M_log.warn("doGet: ", e);
			res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
		finally
		{
			// clear any bound current values
			threadLocalManager().clear();
		}
	}

	/**
	 * Respond to requests.
	 * 
	 * @param req
	 *        The servlet request.
	 * @param res
	 *        The servlet response.
	 * @throws ServletException.
	 * @throws IOException.
	 */
	protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException
	{
		Session s = establishSessionFromCookie(req, res);

		// delay
		if (DELAY)
		{
			try
			{
				Thread.sleep(4 * 1000);
			}
			catch (Exception ignore)
			{
			}
		}

		Map<String, Object> parameters = null;
		try
		{
			// handle the post body
			parameters = processBody(req);

			// dispatch the request based on path
			String path = req.getPathInfo();
			// for e3 gradebook return back from mneme or jforum
			if (s != null && s.getAttribute("etudesgradebook_additionalInfo") != null)
			{
				path = path.concat((String) s.getAttribute("etudesgradebook_additionalInfo"));
				s.setAttribute("etudesgradebook_additionalInfo", "");
			}

			dispatch(req, res, parameters, path);
		}
		catch (Exception e)
		{
			M_log.warn("doPost:", e);
		}
		finally
		{
			processBodyDone(parameters);

			// clear any bound current values
			threadLocalManager().clear();
		}
	}

	/**
	 * @return The EmailService, via the component manager.
	 */
	protected EmailService emailService()
	{
		return (EmailService) ComponentManager.get(EmailService.class);
	}

	/**
	 * @return The EntityManager, via the component manager.
	 */
	protected EntityManager entityManager()
	{
		return (EntityManager) ComponentManager.get(EntityManager.class);
	}

	/**
	 * Check for a session cookie - and if found, set that session as the current session
	 * 
	 * @param req
	 *        The request object.
	 * @param res
	 *        The response object.
	 * @return The Session object if found, else null.
	 */
	protected Session establishSessionFromCookie(HttpServletRequest req, HttpServletResponse res)
	{
		// compute the session cookie suffix, based on this configured server id
		String suffix = System.getProperty(SAKAI_SERVERID);
		if ((suffix == null) || (suffix.length() == 0))
		{
			suffix = "sakai";
		}

		// find our session id from our cookie
		Cookie c = findCookie(req, SESSION_COOKIE, suffix);
		if (c == null) return null;

		// get our session id
		String sessionId = c.getValue();

		// remove the server id suffix
		int dotPosition = sessionId.indexOf(".");
		if (dotPosition > -1)
		{
			sessionId = sessionId.substring(0, dotPosition);
		}

		// find the session
		Session s = sessionManager().getSession(sessionId);

		// mark as active - unless this is the heartbeat request
		if ((s != null) && (!"/heartbeat".equals(req.getPathInfo())))
		{
			s.setActive();
		}

		// set this as the current session
		sessionManager().setCurrentSession(s);

		return s;
	}

	/**
	 * Find a cookie by this name from the request; one with a value that has the specified suffix.
	 * 
	 * @param req
	 *        The servlet request.
	 * @param name
	 *        The cookie name
	 * @param suffix
	 *        The suffix string to find at the end of the found cookie value.
	 * @return The cookie of this name in the request, or null if not found.
	 */
	protected Cookie findCookie(HttpServletRequest req, String name, String suffix)
	{
		Cookie[] cookies = req.getCookies();
		if (cookies != null)
		{
			for (int i = 0; i < cookies.length; i++)
			{
				if (cookies[i].getName().equals(name))
				{
					if ((suffix == null) || cookies[i].getValue().endsWith(suffix))
					{
						return cookies[i];
					}
				}
			}
		}

		return null;
	}

	/**
	 * Format a boolean for transfer.
	 * 
	 * @param b
	 *        The boolean.
	 * @return The boolean as a string.
	 */
	protected String formatBoolean(Boolean b)
	{
		if (b == null) return "0";
		if (b) return "1";
		return "0";
	}

	/**
	 * Format the date for transfer as seconds since the epoc.
	 * 
	 * @param date
	 *        The date.
	 * @return The date as a string.
	 */
	protected String formatDateSecondsSince1970(Date date)
	{
		if (date == null) return "";
		// ms -> sec
		return Long.toString(date.getTime() / 1000);
	}

	/**
	 * Format the time for transfer as seconds since the epoc.
	 * 
	 * @param date
	 *        The date.
	 * @return The date as a string.
	 */
	protected String formatDateSecondsSince1970(Time date)
	{
		if (date == null) return "";
		// ms -> sec
		return Long.toString(date.getTime() / 1000);
	}

	/**
	 * Format a float for transfer
	 * 
	 * @param f
	 *        The float value
	 * @return The float as a string.
	 */
	protected String formatFloat(float f)
	{
		// TODO:
		return Float.toString(f);
	}

	/**
	 * Format an integer for transfer
	 * 
	 * @param i
	 *        The integer value
	 * @return The integer as a string.
	 */
	protected String formatInt(int i)
	{
		return Integer.toString(i);
	}

	/**
	 * Format an integer for transfer
	 * 
	 * @param i
	 *        The integer value
	 * @return The integer as a string.
	 */
	protected String formatInt(Integer i)
	{
		if (i == null) return "0";
		return i.toString();
	}

	/**
	 * Format the parameter map into a client JSON response string.
	 * 
	 * @param parameters
	 *        The parameter map.
	 * @return The client JSON response string.
	 */
	protected String formatResponse(Map<String, Object> parameters)
	{
		ObjectMapper mapper = new ObjectMapper();

		String rv = null;
		try
		{
			rv = mapper.writeValueAsString(parameters);
		}
		catch (JsonGenerationException e)
		{
			M_log.warn("formatResponse: exception:" + e);
		}
		catch (JsonMappingException e)
		{
			M_log.warn("formatResponse: exception:" + e);
		}
		catch (IOException e)
		{
			M_log.warn("formatResponse: exception:" + e);
		}

		return rv;
	}

	/**
	 * Get a list of basic members information for the site.
	 * 
	 * @param context
	 *        The site id.
	 * @return The List of Members for qualified users in the site.
	 */
	@SuppressWarnings("unchecked")
	protected List<SiteMember> getMembers(String context)
	{
		ArrayList<SiteMember> rv = new ArrayList<SiteMember>();
		try
		{
			Site site = siteService().getSite(context);
			Collection<Group> groups = site.getGroups();
			Set<Member> members = site.getMembers();

			for (Member m : members)
			{
				SiteMember p = new SiteMember();
				p.userId = m.getUserId();
				p.role = m.getRole().getId();

				try
				{
					User user = userDirectoryService().getUser(p.userId);
					p.displayName = user.getSortName();
					p.email = user.getEmail();
					p.iid = StringUtil.trimToNull(user.getIidDisplay());
					p.eid = user.getEid();
				}
				catch (UserNotDefinedException e)
				{
					// skip deleted users
					continue;
				}

				// provided results in status enrolled / blocked / dropped
				if (m.isProvided())
				{
					if (m.getRole().getId().equals("Blocked") || ((!m.isActive()) && m.getRole().getId().equals("Observer")))
					{
						p.status = CdpParticipantStatus.blocked;
					}
					else if (m.isActive())
					{
						p.status = CdpParticipantStatus.enrolled;
					}
					else
					{
						p.status = CdpParticipantStatus.dropped;
					}
				}

				// non-provided results in status active / inactive
				else
				{
					if (m.isActive())
					{
						p.status = CdpParticipantStatus.active;
					}
					else
					{
						p.status = CdpParticipantStatus.inactive;
					}
				}

				// outright skip guests
				// if (m.getRole().getId().equalsIgnoreCase("guest"))
				// {
				// continue;
				// }

				// skip blocked
				// if (m.getRole().getId().equals("Blocked"))
				// {
				// continue;
				// }

				// else if (site.isAllowed(userId, "section.role.student"))
				// {
				// status = ParticipantStatus.enrolled;
				// }

				// skip not active
				// else if (!m.isActive())
				// {
				// continue;
				// }

				/*
				 * This was CDP 1.0: if (m.getRole().getId().equals("Blocked")) { p.status = ParticipantStatus.blocked; }
				 * 
				 * else if (site.isAllowed(p.userId, "section.role.student")) { p.status = ParticipantStatus.enrolled; }
				 * 
				 * else if (!m.isActive()) { // check for inactive users of the role that has this access Set roles = site.getRolesIsAllowed("section.role.student"); if (roles.contains(m.getRole().getId())) { p.status = ParticipantStatus.dropped; } }
				 */

				// which site group is the user in?
				// String groupTitle = null;
				// Collection groups = site.getGroups();
				// for (Object groupO : groups)
				// {
				// Group g = (Group) groupO;
				// if (g.getUsers().contains(userId))
				// {
				// groupTitle = g.getTitle();
				// }
				// }

				// get the JForum user profile
				org.etudes.api.app.jforum.User u = jForumUserService().getBySakaiUserId(p.userId);
				if (u != null)
				{
					p.showEmail = u.isViewEmailEnabled();
					if (!p.showEmail) p.email = null;
					p.avatar = StringUtil.trimToNull(u.getAvatar());
					p.website = StringUtil.trimToNull(u.getWebSite());
					p.aim = StringUtil.trimToNull(u.getAim());
					p.msn = StringUtil.trimToNull(u.getMsnm());
					p.yahoo = StringUtil.trimToNull(u.getYim());
					p.facebook = StringUtil.trimToNull(u.getFaceBookAccount());
					p.twitter = StringUtil.trimToNull(u.getTwitterAccount());
					p.occupation = StringUtil.trimToNull(u.getOccupation());
					p.interests = StringUtil.trimToNull(u.getInterests());
					p.location = StringUtil.trimToNull(u.getFrom());
					p.googlePlus = StringUtil.trimToNull(u.getGooglePlus());
					p.linkedIn = StringUtil.trimToNull(u.getLinkedIn());
					p.skype = StringUtil.trimToNull(u.getSkype());
				}

				// which section is the user in? If in multiple, pick the one that is active, if any. Otherwise, just pick any.
				String titleActive = null;
				String titleInactive = null;
				for (Group g : groups)
				{
					// skip non-section groups
					if (g.getProperties().getProperty("sections_category") == null) continue;

					// we want to find the user even if not active, so we cannot use g.getUsers(), which only returns active users -ggolden
					// if (g.getUsers().contains(userId))
					Set<Member> groupMemebers = g.getMembers();
					for (Member gm : groupMemebers)
					{
						if (gm.getUserId().equals(m.getUserId()))
						{
							if (gm.isActive())
							{
								if (titleActive == null) titleActive = g.getTitle();
							}
							else
							{
								if (titleInactive == null) titleInactive = g.getTitle();
							}
						}
					}
				}
				if (titleActive != null)
				{
					p.groupTitle = titleActive;
				}
				else if (titleInactive != null)
				{
					p.groupTitle = titleInactive;
				}

				rv.add(p);
			}
		}
		catch (IdUnusedException e)
		{
			M_log.warn("getParticipants: missing site: " + context);
		}

		// sort by display name
		Collections.sort(rv, new Comparator<SiteMember>()
		{
			public int compare(SiteMember arg0, SiteMember arg1)
			{
				return arg0.displayName.compareToIgnoreCase(arg1.displayName);
			}
		});

		return rv;
	}

	/**
	 * Check if the string exists and has characters.
	 * 
	 * @param s
	 *        The string to check.
	 * @return true if the string exists with length, false if null or empty.
	 */
	protected boolean hasLength(String s)
	{
		if (s == null) return false;
		if (s.length() == 0) return false;
		return true;
	}

	/**
	 * Check if the set exists an d has items.
	 * 
	 * @param s
	 *        The set to check.
	 * @return true if the set exists with items, false if null or empty.
	 */
	@SuppressWarnings("rawtypes")
	protected boolean hasSize(Set s)
	{
		if (s == null) return false;
		if (s.size() == 0) return false;
		return true;
	}

	/**
	 * Check if this URL is being hosted by us on this server - with a non-relative URL. Consider the primary and also any alternate URL roots.
	 * 
	 * @param url
	 *        The url to check.
	 * @return -1 if not, or the index position in the url of the start of the relative portion (i.e. after the server URL root)
	 */
	protected int internallyHostedUrl(String url)
	{
		// form the access root, and check for alternate ones
		String serverUrl = serverConfigurationService().getServerUrl();
		String[] alternateUrls = serverConfigurationService().getStrings("alternateServerUrlRoots");

		if (url.startsWith(serverUrl)) return serverUrl.length();
		if (alternateUrls != null)
		{
			for (String alternateUrl : alternateUrls)
			{
				if (url.startsWith(alternateUrl)) return alternateUrl.length();
			}
		}

		return -1;
	}

	/**
	 * Determine if message viewable based on release date (if set)
	 */
	protected boolean isAnnouncementViewable(AnnouncementMessage message)
	{
		final Time now = timeService().newTime();
		try
		{
			final Time releaseDate = message.getProperties().getTimeProperty(AnnouncementService.RELEASE_DATE);

			if (now.before(releaseDate))
			{
				return false;
			}
		}
		catch (Exception e)
		{
		}

		return true;
	}

	/**
	 * Check if the identified user has the "instructor" status in the SiteMembers list.
	 * 
	 * @param members
	 *        The list of members of the site.
	 * @param userId
	 *        The user id of the user to check.
	 * @return true if found and an instructor, false if not.
	 */
	protected boolean isInstructor(List<SiteMember> members, String userId)
	{
		for (SiteMember mbr : members)
		{
			if (mbr.userId.equals(userId))
			{
				return (mbr.status == null);
			}
		}
		return false;
	}

	/**
	 * @return The JForumCategoryService, via the component manager.
	 */
	protected JForumCategoryService jForumCategoryService()
	{
		return (JForumCategoryService) ComponentManager.get(JForumCategoryService.class);
	}

	/**
	 * @return The JForumForumService, via the component manager.
	 */
	protected JForumForumService jForumForumService()
	{
		return (JForumForumService) ComponentManager.get(JForumForumService.class);
	}

	/**
	 * @return The JForumGradeService, via the component manager.
	 */
	protected JForumGradeService jForumGradeService()
	{
		return (JForumGradeService) ComponentManager.get(JForumGradeService.class);
	}

	/**
	 * @return The JForumPostService, via the component manager.
	 */
	protected JForumPostService jForumPostService()
	{
		return (JForumPostService) ComponentManager.get(JForumPostService.class);
	}

	/**
	 * @return The JForumPrivateMessageService, via the component manager.
	 */
	protected JForumPrivateMessageService jForumPrivateMessageService()
	{
		return (JForumPrivateMessageService) ComponentManager.get(JForumPrivateMessageService.class);
	}

	/**
	 * @return The JForumSynopticService, via the component manager.
	 */
	protected JForumSynopticService jforumSynopticService()
	{
		return (org.etudes.api.app.jforum.JForumSynopticService) ComponentManager.get(org.etudes.api.app.jforum.JForumSynopticService.class);
	}

	/**
	 * @return The JForumUserService, via the component manager.
	 */
	protected JForumUserService jForumUserService()
	{
		return (JForumUserService) ComponentManager.get(JForumUserService.class);
	}

	protected void loadAssessment(Assessment a, Map<String, String> assessmentMap)
	{
		assessmentMap.put("assessmentId", a.getId());
		assessmentMap.put("type", a.getType().name());
		assessmentMap.put("title", a.getTitle());
		// formatDateSecondsSince1970 ??
		assessmentMap.put("open", CdpResponseHelper.dateTimeDisplayInUserZone(a.getDates().getOpenDate().getTime()));
		assessmentMap.put("due", CdpResponseHelper.dateTimeDisplayInUserZone(a.getDates().getDueDate().getTime()));
		assessmentMap.put("allow", CdpResponseHelper.dateTimeDisplayInUserZone(a.getDates().getAcceptUntilDate().getTime()));
		assessmentMap.put("published", formatBoolean(a.getPublished()));
		assessmentMap.put("specialAccess", formatBoolean(a.getSpecialAccess().getIsDefined()));
	}

	protected void loadCourseMap(CourseMapMap map, Map<String, Object> mapMap)
	{
		// the main map has an "items" entry - a list of maps for each item
		List<Map<String, String>> itemsMap = new ArrayList<Map<String, String>>();
		mapMap.put("items", itemsMap);

		// process each item
		for (CourseMapItem item : map.getItems())
		{
			Map<String, String> itemMap = new HashMap<String, String>();
			itemsMap.add(itemMap);

			CourseMapItem blockedBy = item.getBlockedBy();

			itemMap.put("accessStatus", formatInt(item.getAccessStatus().getId()));
			itemMap.put("allowUntil", formatDateSecondsSince1970(item.getClose()));
			itemMap.put("blocked", formatBoolean(item.getBlocked()));
			if (blockedBy != null) itemMap.put("blockedByMapId", blockedBy.getMapId());
			itemMap.put("blocker", formatBoolean(item.getBlocker()));
			if (item.getCount() != null) itemMap.put("count", formatInt(item.getCount()));
			if (item.getCountRequired() != null) itemMap.put("countRequired", formatInt(item.getCountRequired()));
			if (item.getDue() != null) itemMap.put("due", formatDateSecondsSince1970(item.getDue()));
			if (item.getFinished() != null) itemMap.put("finished", formatDateSecondsSince1970(item.getFinished()));
			if (item.getSuppressFinished()) itemMap.put("suppressFinished", formatBoolean(item.getSuppressFinished()));
			itemMap.put("complete", formatBoolean(item.getIsComplete()));
			itemMap.put("incomplete", formatBoolean(item.getIsIncomplete()));
			List<CourseMapItemDisplayStatus> info = item.getItemDisplayStatus();
			itemMap.put("itemDisplayStatus1", formatInt(info.get(0).getId()));
			itemMap.put("itemDisplayStatus2", formatInt(info.get(1).getId()));
			itemMap.put("mapId", item.getMapId());
			itemMap.put("mapPosition", formatInt(item.getMapPosition()));
			itemMap.put("mastered", formatBoolean(item.getMastered()));
			itemMap.put("masteryLevelQualified", formatBoolean(item.getMasteryLevelQualified()));
			if (item.getMasteryLevelScore() != null) itemMap.put("masteryLevelScore", formatFloat(item.getMasteryLevelScore()));
			itemMap.put("multipleRequired", formatBoolean(item.getMultipleCountRequired()));
			itemMap.put("notMasteredAlert", formatBoolean(item.getNotMasteredAlert()));
			if (item.getOpen() != null) itemMap.put("open", formatDateSecondsSince1970(item.getOpen()));
			if (item.getPerformStatus() != null) itemMap.put("performStatus", formatInt(item.getPerformStatus().getId()));
			if (item.getPoints() != null) itemMap.put("points", formatFloat(item.getPoints()));
			itemMap.put("providerId", item.getId());
			itemMap.put("requiresMastery", formatBoolean(item.getRequiresMastery()));
			if (item.getScore() != null) itemMap.put("score", item.getScore().toString());
			if (item.getScoreStatus() != null) itemMap.put("scoreStatus", formatInt(item.getScoreStatus().getId()));
			if (item.getTitle() != null) itemMap.put("title", item.getTitle());

			// Map for inTouch, which does not yet know about fce or offline
			CourseMapItemType t = item.getType();
			if (t == CourseMapItemType.fce)
			{
				t = CourseMapItemType.survey;
			}
			else if (t == CourseMapItemType.offline)
			{
				t = CourseMapItemType.assignment;
			}
			itemMap.put("type", formatInt(t.getId()));
			itemMap.put("progressStatus", formatInt(item.getProgressStatus().getId()));
		}
	}

	protected boolean loadForum(Category c, Forum f, Map<String, String> forumMap, String userId, String siteId)
	{
		forumMap.put("forumId", Integer.toString(f.getId()));
		String cid = Integer.toString(c.getId());
		forumMap.put("categoryId", cid);
		forumMap.put("title", f.getName());
		if (f.getDescription() != null) forumMap.put("description", f.getDescription());
		if (f.getAccessDates().getOpenDate() != null) forumMap.put("open", formatDateSecondsSince1970(f.getAccessDates().getOpenDate()));
		if (f.getAccessDates().getDueDate() != null) forumMap.put("due", formatDateSecondsSince1970(f.getAccessDates().getDueDate()));
		if (f.getAccessDates().getAllowUntilDate() != null)
			forumMap.put("allowUntil", formatDateSecondsSince1970(f.getAccessDates().getAllowUntilDate()));
		forumMap.put("hideTillOpen", formatBoolean(f.getAccessDates().isHideUntilOpen()));
		// deny access means unpublished
		forumMap.put("published", formatBoolean(f.getAccessType() != Forum.ACCESS_DENY));
		boolean graded = false;
		if (f.getGrade() != null)
		{
			forumMap.put("minPosts", Integer.toString(f.getGrade().getMinimumPosts()));
			forumMap.put("points", formatFloat(f.getGrade().getPoints()));
			graded = (f.getGrade().getType() == Grade.GRADE_BY_FORUM);
		}
		forumMap.put("graded", formatBoolean(graded));
		forumMap.put("lockOnDue", formatBoolean(false)); // TODO: remove in sync with inTouch
		forumMap.put("pastDueLocked", formatBoolean(pastDueAndLocked(c.getAccessDates(), f.getAccessDates(), null)));
		boolean notYetOpen = notYetOpen(c.getAccessDates(), f.getAccessDates(), null);
		forumMap.put("notYetOpen", formatBoolean(notYetOpen));

		// figure the type: 0-normal, 1-replyOnly, 2-readOnly
		String type = "0";
		if (f.getType() == Forum.ForumType.REPLY_ONLY.getType())
		{
			type = "1";
		}
		else if (f.getType() == Forum.ForumType.READ_ONLY.getType())
		{
			type = "2";
		}
		forumMap.put("type", type);

		forumMap.put("numTopics", Integer.toString(f.getTotalTopics()));
		forumMap.put("unread", formatBoolean(f.isUnread()));

		if (f.getBlocked())
		{
			forumMap.put("blocked", f.getBlockedByTitle());
		}
		else if (c.getBlocked())
		{
			forumMap.put("blocked", c.getBlockedByTitle());
		}

		// until inTouch 2, if notYetOpen, and not an instructor, skip it
		if (notYetOpen)
		{
			boolean managePrivileges = checkSecurity(userId, "jforum.manage", siteId);
			if (!managePrivileges) return false;
		}

		return true;
	}

	protected void loadModule(ModuleObjService module, Map<String, Object> moduleMap, String userId)
	{
		moduleMap.put("title", module.getTitle());

		// "sections" entry - a list of maps for each section
		List<Map<String, String>> sectionsMap = new ArrayList<Map<String, String>>();
		moduleMap.put("sections", sectionsMap);

		// process each section
		List<SectionObjService> sections = sectionService().getSections(module);
		for (SectionObjService section : sections)
		{
			Map<String, String> sectionMap = new HashMap<String, String>();
			sectionsMap.add(sectionMap);

			Map<String, Date> viewed = null;
			try
			{
				viewed = sectionService().getSectionViewDates(section.getSectionId().toString());
			}
			catch (Exception e)
			{
				M_log.warn("loadModule - getSectionViewDates: " + e);
				viewed = new HashMap<String, Date>();
			}

			sectionMap.put("title", section.getTitle());
			// /private/meleteDocs/f9bdb161-0ffe-4f7b-00f9-5d040a4bcec2/module_1998848/Section_2031617.html add /access/content prefix
			sectionMap.put("sectionId", formatInt(section.getSectionId()));

			Date viewedDate = viewed.get(userId);
			if (viewedDate != null) sectionMap.put("viewed", formatDateSecondsSince1970(viewedDate));

			// TODO: more section stuff
		}
	}

	protected void loadNews(AnnouncementMessage msg, Map<String, String> messageMap, boolean bodyNotPath, boolean plainText)
	{
		messageMap.put("subject", msg.getAnnouncementHeader().getSubject());
		messageMap.put("messageId", msg.getReference());
		messageMap.put("date", formatDateSecondsSince1970(msg.getAnnouncementHeader().getDate()));
		messageMap.put("from", msg.getAnnouncementHeader().getFrom().getDisplayName());
		messageMap.put("fromUserId", msg.getAnnouncementHeader().getFrom().getId());

		if (bodyNotPath)
		{
			String body = msg.getBody();
			if (plainText)
			{
				body = StringHtml.plainFromHtml(body);
			}
			else
			{
				body = accessToCdpDoc(body, false);
			}
			messageMap.put("body", body);
		}
		else
		{
			messageMap.put("bodyPath", "/cdp/doc/announcement" + msg.getReference());
		}

		// TODO: update if we start tracking reads of announcements in Etudes -ggolden
		messageMap.put("unread", formatBoolean(false));
		messageMap.put("draft", formatBoolean(msg.getHeader().getDraft()));

		String priorityStr = msg.getProperties().getProperty(AnnouncementService.NOTIFICATION_LEVEL);
		Boolean priority = ((priorityStr == null) ? Boolean.FALSE : Boolean.valueOf(priorityStr.equals("r")));
		messageMap.put("priority", formatBoolean(priority));

		try
		{
			Time releaseDate = msg.getProperties().getTimeProperty(AnnouncementService.RELEASE_DATE);
			if (releaseDate != null) messageMap.put("releaseDate", formatDateSecondsSince1970(releaseDate));
		}
		catch (EntityPropertyNotDefinedException e)
		{
		}
		catch (EntityPropertyTypeException e)
		{
		}
	}

	protected void loadPool(Pool p, Map<String, String> poolMap)
	{
		poolMap.put("poolId", p.getId());
		poolMap.put("title", p.getTitle());
		poolMap.put("description", p.getDescription());
		poolMap.put("questions", formatInt(p.getNumQuestions()));
		poolMap.put("points", formatFloat(p.getPoints()));
		poolMap.put("difficulty", formatInt(p.getDifficulty()));
	}

	protected void loadPost(Post p, Map<String, String> messageMap, boolean fromInstructor)
	{
		messageMap.put("subject", p.getSubject());
		messageMap.put("postId", Integer.toString(p.getId()));
		messageMap.put("date", formatDateSecondsSince1970(p.getTime()));
		if (!p.getEditTime().equals(p.getTime())) messageMap.put("revised", formatDateSecondsSince1970(p.getEditTime()));
		messageMap.put("from", p.getPostedBy().getFirstName() + " " + p.getPostedBy().getLastName());
		messageMap.put("fromUserId", p.getPostedBy().getSakaiUserId());

		// body is html fragment mixed with [quote] and other possible bbcode tags, internal link set to myEtudes access links
		// render it as a full html document
		String fragment = StringUtil.trimToZero(p.getRawText());
		fragment = StringHtml.htmlFromBbCode(fragment);
		fragment = StringHtml.htmlFromQuote(fragment);

		// any image attachments get inserted here, inline
		boolean otherAttachments = false;
		List<Attachment> attachments = p.getAttachments();
		if ((attachments != null) && (!attachments.isEmpty()))
		{
			for (Attachment attachment : attachments)
			{
				if (attachment.getInfo().getMimetype().startsWith("image/"))
				{
					String url = "/cdp/doc/jfa/" + attachment.getId();
					fragment += "<figure><img src=\"" + url + "\" alt=\"" + attachment.getInfo().getRealFilename() + "\"><figcaption><a href=\""
							+ url + "\">" + attachment.getInfo().getRealFilename() + "</a></figcaption></figure>";
				}
				else
				{
					otherAttachments = true;
				}
			}
		}

		fragment = accessToCdpDoc(fragment, false);

		// add a full document wrapper
		StringBuilder body = new StringBuilder();
		body.append("<html><head>\n");
		body.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
		body.append("<script type=\"text/javascript\" src=\"/ckeditor/ckeditor/plugins/ckeditor_wiris/core/WIRISplugins.js?viewer=image\" defer=\"defer\"></script>");
		body.append("</head><body>\n");
		body.append(fragment);
		if (otherAttachments && (attachments != null) && (!attachments.isEmpty()))
		{
			body.append("<h4 style=\"font-size:1em;color:#555;margin:1em 1em .2em 0;\">Attachments</h4><ul>\n");
			for (Attachment attachment : attachments)
			{
				if (!attachment.getInfo().getMimetype().startsWith("image/"))
				{
					String url = "/cdp/doc/jfa/" + attachment.getId();
					// switch to a cdp/doc from /access
					String link = accessToCdpDoc("<a href=\"" + url + "\">", false);
					String description = attachment.getInfo().getRealFilename();
					body.append("<li>" + link + description + "</a></li>\n");
				}
			}
			body.append("</ul>");
		}
		body.append("</body></html>");
		messageMap.put("body", body.toString());

		messageMap.put("fromInstructor", formatBoolean(fromInstructor));

		// full avatar path relative to server
		// TODO: part of this from config?
		if (p.getPostedBy().getAvatar() != null)
		{
			// String avatarPath = "/jforum-images/images/avatar/" + p.getPostedBy().getAvatar();
			String avatarPath = "/cdp/doc/avatar/" + p.getPostedBy().getAvatar();
			messageMap.put("avatar", avatarPath);
		}

		messageMap.put("mayEdit", formatBoolean(p.isCanEdit()));
	}

	protected void loadPresenceUser(String userId, boolean inChat, Map<String, String> userMap)
	{
		try
		{
			User u = this.userDirectoryService().getUser(userId);
			userMap.put("name", u.getDisplayName());
		}
		catch (UserNotDefinedException e)
		{
		}

		userMap.put("userId", userId);
		userMap.put("chat", formatBoolean(inChat));
	}

	protected void loadSite(Site site, Map<String, Object> siteMap, boolean visible, String userId, boolean includeStatus, boolean includeTools,
			Map<String, Integer> unreadPmCounts, boolean intouchSiteFormat)
	{
		siteMap.put("siteId", site.getId());
		siteMap.put("title", site.getTitle());

		if (site.getShortDescription() != null) siteMap.put("description", site.getShortDescription());

		// permissions
		siteMap.put("am", formatBoolean(activityMeterService().allowActivityAccess(site.getId(), userId)));
		siteMap.put("cm", formatBoolean(courseMapService().allowGetMap(site.getId(), userId)));
		String channelId = announcementService().channelReference(site.getId(), SiteService.MAIN_CONTAINER);
		siteMap.put("announcement", formatBoolean(announcementService().allowEditChannel(channelId)));
		// TODO: do a security check for the instructor tag permission?
		boolean amAllowed = activityMeterService().allowActivityAccess(site.getId(), userId);
		siteMap.put("instructorPrivileges", formatBoolean(amAllowed));

		boolean taPrivileges = checkSecurity(userId, "section.role.ta", site.getId());
		siteMap.put("taPrivileges", formatBoolean(taPrivileges));

		boolean visitUnp = checkSecurity(userId, "site.visit.unp", site.getId());
		siteMap.put("visitUnpublished", formatBoolean(visitUnp));

		siteMap.put("visible", formatBoolean(visible));

		// we don't need status for unpublished sites
		if (includeStatus && site.isPublished())
		{
			// online
			if (intouchSiteFormat)
			{
				@SuppressWarnings("rawtypes")
				List users = presenceService().getPresentUsers(site.getId() + "-presence");
				siteMap.put("online", formatInt(users.size()));
			}
			else
			{
				Integer presenceCount = presenceService().countPresence(site.getId() + "-presence");
				siteMap.put("online", formatInt(presenceCount));
			}

			// unread messages
			if (intouchSiteFormat)
			{
				// unread messages
				int unreadCount = 0;
				List<PrivateMessage> msgs = jForumPrivateMessageService().inbox(site.getId(), userId);
				for (PrivateMessage m : msgs)
				{
					if (m.getType() == PrivateMessage.TYPE_NEW) unreadCount++;
				}
				siteMap.put("unreadMessages", formatInt(unreadCount));
			}
			else
			{
				Integer count = unreadPmCounts.get(site.getId());
				if (count == null) count = Integer.valueOf(0);
				siteMap.put("unreadMessages", formatInt(count));
			}

			// unread posts
			if (intouchSiteFormat)
			{
				boolean unreadPosts = jForumCategoryService().isUserHasUnreadTopicsAndReplies(site.getId(), userId);
				siteMap.put("unreadPosts", formatBoolean(unreadPosts));
			}
			else
			{
				int unreadPosts = jForumCategoryService().getUserUnreadTopicsCount(site.getId(), userId);
				siteMap.put("unreadPosts", formatInt(unreadPosts));
			}

			// alert users (only check if we allow AM access)
			int notVisitedCount = 0;
			if (amAllowed)
			{
				notVisitedCount = this.dataHelper.getSiteStudentNotVisitedInPeriod(site.getId(), 7);
			}
			siteMap.put("notVisitAlerts", formatInt(notVisitedCount));

			// mneme reviews
			if (!intouchSiteFormat)
			{
				int reviewCount = 0;
				if (!amAllowed)
				{
					List<Submission> submissions = submissionService().getUserContextSubmissions(site.getId(), null, null);
					for (Submission s : submissions)
					{
						if (s.getEvaluationNotReviewed()) reviewCount++;
					}
				}
				siteMap.put("reviewCountMneme", formatInt(reviewCount));
			}

			// jforum reviews
			if (!intouchSiteFormat)
			{
				int reviewCount = jForumGradeService().getUserNotReviewedGradeEvaluationsCount(site.getId(), userId);
				siteMap.put("reviewCountJForum", formatInt(reviewCount));
			}
		}

		if (includeTools)
		{
			// site tool layout
			List<Map<String, String>> toolsMap = new ArrayList<Map<String, String>>();
			siteMap.put("tools", toolsMap);

			// TODO:
			// {"name": "HOME", "tool": "home1", "l_url":"Gateway/gateway_world.gif", "l_type":"image/gif"},
			// {"name": "AT&S", "tool": "mneme"}
			Map<String, String> toolMap = new HashMap<String, String>();
			toolsMap.add(toolMap);
			toolMap.put("name", "HOME");
			toolMap.put("tool", "homepage");
			toolMap.put("l_url", "Gateway/gateway_world.gif");
			toolMap.put("l_type", "image/gif");

			toolMap = new HashMap<String, String>();
			toolsMap.add(toolMap);
			toolMap.put("name", "AT&S");
			toolMap.put("tool", "mneme");
		}

		siteMap.put("presence", formatBoolean(true));

		siteMap.put("published", formatBoolean(site.isPublished()));
		siteMap.put("created", CdpResponseHelper.dateTimeDisplayInUserZone(site.getCreatedTime().getTime()));
		siteMap.put("type", "course".equalsIgnoreCase(site.getType()) ? "Course" : "Project");
		siteMap.put("owner", site.getCreatedBy().getSortName());
		siteMap.put("term", describeTerm(site.getTermSuffix()));
		siteMap.put("termId", site.getTermId());

		// Note: copied from SiteAction.java
		if (site.getProperties().getProperty("pub-date") != null)
		{
			try
			{
				// Note: originally, the date was stored in properties as input format, default time zone, rather than as a Time property -ggolden
				// If we fix this, we read the value with Time pubTime = siteProperties.getTimeProperty(PROP_SITE_PUB_DATE);
				String pubValue = site.getProperties().getProperty("pub-date");
				Date pubDate = DateHelper.parseDateFromDefault(pubValue);
				siteMap.put("publishOn", CdpResponseHelper.dateTimeDisplayInUserZone(pubDate.getTime()));

				// if this is in the future
				if (pubDate.after(new Date()))
				{
					siteMap.put("willPublish", formatBoolean(true));
				}
			}
			catch (ParseException e)
			{
			}
		}
		if (site.getProperties().getProperty("unpub-date") != null)
		{
			try
			{
				// Note: originally, the date was stored in properties as input format, default time zone, rather than as a Time property -ggolden
				// If we fix this, we read the value with Time pubTime = siteProperties.getTimeProperty(PROP_SITE_UNPUB_DATE);
				String unpubValue = site.getProperties().getProperty("unpub-date");
				Date unpubDate = DateHelper.parseDateFromDefault(unpubValue);
				siteMap.put("unpublishOn", CdpResponseHelper.dateTimeDisplayInUserZone(unpubDate.getTime()));
			}
			catch (ParseException e)
			{
			}
		}
	}

	protected boolean loadTopic(Category c, Forum f, Topic t, Map<String, String> topicMap, String userId, String siteId)
	{
		topicMap.put("topicId", Integer.toString(t.getId()));
		topicMap.put("title", t.getTitle());
		topicMap.put("author", t.getLastPostBy().getFirstName() + " " + t.getLastPostBy().getLastName());

		// figure the type: 0-normal, 1-announce, 2-sticky, 3-reuse
		String type = "0";
		if (t.getType() == Topic.TopicType.ANNOUNCE.getType())
		{
			type = "1";
		}
		else if (t.getType() == Topic.TopicType.STICKY.getType())
		{
			type = "2";
		}
		else if (t.isExportTopic())
		{
			type = "3";
		}
		topicMap.put("type", type);

		topicMap.put("readOnly", formatBoolean(t.getStatus() == Topic.STATUS_LOCKED));
		topicMap.put("forumReadOnly", formatBoolean(f.getType() == Forum.ForumType.READ_ONLY.getType()));
		topicMap.put("numPosts", Integer.toString(1 + t.getTotalReplies()));
		topicMap.put("unread", formatBoolean(!t.getRead()));

		if (t.getAccessDates().getOpenDate() != null) topicMap.put("open", formatDateSecondsSince1970(t.getAccessDates().getOpenDate()));
		if (t.getAccessDates().getDueDate() != null) topicMap.put("due", formatDateSecondsSince1970(t.getAccessDates().getDueDate()));
		if (t.getAccessDates().getAllowUntilDate() != null)
			topicMap.put("allowUntil", formatDateSecondsSince1970(t.getAccessDates().getAllowUntilDate()));
		topicMap.put("hideTillOpen", formatBoolean(t.getAccessDates().isHideUntilOpen()));
		topicMap.put("published", formatBoolean(f.getAccessType() != Forum.ACCESS_DENY));

		boolean graded = false;
		if (t.getGrade() != null)
		{
			topicMap.put("minPosts", Integer.toString(t.getGrade().getMinimumPosts()));
			topicMap.put("points", formatFloat(t.getGrade().getPoints()));
			graded = (t.getGrade().getType() == Grade.GRADE_BY_TOPIC);
		}
		topicMap.put("graded", formatBoolean(graded));
		topicMap.put("lockOnDue", formatBoolean(false)); // TODO: remove in sync with inTouch
		topicMap.put("latestPost", formatDateSecondsSince1970(t.getLastPostTime()));
		topicMap.put("pastDueLocked", formatBoolean(pastDueAndLocked(c.getAccessDates(), f.getAccessDates(), t.getAccessDates())));
		boolean notYetOpen = notYetOpen(c.getAccessDates(), f.getAccessDates(), t.getAccessDates());
		topicMap.put("notYetOpen", formatBoolean(notYetOpen));

		if (t.getBlocked())
		{
			topicMap.put("blocked", t.getBlockedByTitle());
		}
		else if (f.getBlocked())
		{
			topicMap.put("blocked", f.getBlockedByTitle());
		}
		else if (c.getBlocked())
		{
			topicMap.put("blocked", c.getBlockedByTitle());
		}

		topicMap.put("mayPost", formatBoolean(t.mayPost()));

		// until inTouch 2, if notYetOpen, and not an instructor, skip it
		if (notYetOpen)
		{
			boolean managePrivileges = checkSecurity(userId, "jforum.manage", siteId);
			if (!managePrivileges) return false;
		}

		return true;
	}

	/**
	 * Find the member's iid from the list of members
	 * 
	 * @param members
	 *        The list of members if the site.
	 * @param userId
	 *        The user id to check.
	 * @return The user's iid, or null if not found.
	 */
	protected String memberIid(List<SiteMember> members, String userId)
	{
		for (SiteMember mbr : members)
		{
			if (mbr.userId.equals(userId))
			{
				return (mbr.iid);
			}
		}
		return null;
	}

	/**
	 * @return The ModuleService, via the component manager.
	 */
	protected ModuleService moduleService()
	{
		return (ModuleService) ComponentManager.get(ModuleService.class);
	}

	/**
	 * Figure if these dates indicate that the item is not yet open.
	 * 
	 * @param catDates
	 *        The category dates.
	 * @param forumDates
	 *        The forum dates.
	 * @param topicDates
	 *        The topic dates.
	 * @return true if it is not yet open, false if not.
	 */
	protected boolean notYetOpen(AccessDates catDates, AccessDates forumDates, AccessDates topicDates)
	{
		// use one of the sets of dates
		if ((topicDates != null) && ((topicDates.getOpenDate() != null) || (topicDates.getDueDate() != null)))
		{
			if (topicDates.getOpenDate() != null)
			{
				if (new Date().before(topicDates.getOpenDate()))
				{
					return true;
				}
			}
		}
		else if ((forumDates != null) && ((forumDates.getOpenDate() != null) || (forumDates.getDueDate() != null)))
		{
			if (forumDates.getOpenDate() != null)
			{
				if (new Date().before(forumDates.getOpenDate()))
				{
					return true;
				}
			}
		}
		else if ((catDates != null) && ((catDates.getOpenDate() != null) || (catDates.getDueDate() != null)))
		{
			if (catDates.getOpenDate() != null)
			{
				if (new Date().before(catDates.getOpenDate()))
				{
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Figure if these dates indicate that the item is past due, (due or allow until).
	 * 
	 * @param catDates
	 *        The category dates.
	 * @param forumDates
	 *        The forum dates.
	 * @param topicDates
	 *        The topic dates.
	 * @return true if it is past due / allow until, false if not.
	 */
	protected boolean pastDueAndLocked(AccessDates catDates, AccessDates forumDates, AccessDates topicDates)
	{
		// use one of the sets of dates
		if ((topicDates != null)
				&& ((topicDates.getOpenDate() != null) || (topicDates.getDueDate() != null) || (topicDates.getAllowUntilDate() != null)))
		{
			if (topicDates.getAllowUntilDate() != null)
			{
				if (new Date().after(topicDates.getAllowUntilDate()))
				{
					return true;
				}
			}
			else if (topicDates.getDueDate() != null)
			{
				if (new Date().after(topicDates.getDueDate()))
				{
					return true;
				}
			}
		}
		else if ((forumDates != null)
				&& ((forumDates.getOpenDate() != null) || (forumDates.getDueDate() != null) || (forumDates.getAllowUntilDate() != null)))
		{
			if (forumDates.getAllowUntilDate() != null)
			{
				if (new Date().after(forumDates.getAllowUntilDate()))
				{
					return true;
				}
			}
			else if (forumDates.getDueDate() != null)
			{
				if (new Date().after(forumDates.getDueDate()))
				{
					return true;
				}
			}
		}
		else if ((catDates != null)
				&& ((catDates.getOpenDate() != null) || (catDates.getDueDate() != null) || (catDates.getAllowUntilDate() != null)))
		{
			if (catDates.getAllowUntilDate() != null)
			{
				if (new Date().after(catDates.getAllowUntilDate()))
				{
					return true;
				}
			}
			else if (catDates.getDueDate() != null)
			{
				if (new Date().after(catDates.getDueDate()))
				{
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Process the request URL parameters and post body data to form a map of all parameters
	 * 
	 * @param req
	 *        The request.
	 * @return The map of parameters: keyed by parameter name, values either String, String[], or (later) file.
	 */
	protected Map<String, Object> processBody(HttpServletRequest req)
	{
		// keyed by name, value can be String, String[], or (later) a file
		Map<String, Object> rv = new HashMap<String, Object>();

		// Create a factory for disk-based file items, with a 30k memory threshold (larger items stream to a temp file)
		DiskFileItemFactory factory = new DiskFileItemFactory();
		factory.setSizeThreshold(30 * 1024);

		// hook up the context's tracker (see the listener in web.xml)
		// docs (https://commons.apache.org/proper/commons-fileupload/using.html) recommend, but does not seem to be needed: the finalizer on the DiskFileItem does as well -ggolden
		// ServletContext context = getServletContext();
		// FileCleaningTracker fileCleaningTracker = FileCleanerCleanup.getFileCleaningTracker(context);
		// factory.setFileCleaningTracker(fileCleaningTracker);

		// Create a new file upload handler
		ServletFileUpload upload = new ServletFileUpload(factory);

		String encoding = req.getCharacterEncoding();
		if ((encoding != null) && (encoding.length() > 0)) upload.setHeaderEncoding(encoding);

//		System.out.println("CDP: tracker: " + factory.getFileCleaningTracker() + " threshold: " + factory.getSizeThreshold() + " repo: "
//				+ factory.getRepository() + " fileSizeMax: " + upload.getFileSizeMax() + " sizeMax: " + upload.getSizeMax());

		// Parse the request
		try
		{
			List<FileItem> items = upload.parseRequest(req);
			for (FileItem item : items)
			{
				if (item.isFormField())
				{
//					System.out.println("CDP: isFormField: " + item.getFieldName() + " : inMemory: " + item.isInMemory() + " size: " + item.getSize());

					// the key
					String key = item.getFieldName();

					// the value
					String value = item.getString("UTF-8");

					// merge into our map of key / values
					Object current = rv.get(item.getFieldName());

					// if not there, start with the value
					if (current == null)
					{
						rv.put(key, value);
					}

					// if we find a value, change it to an array containing both
					else if (current instanceof String)
					{
						String[] values = new String[2];
						values[0] = (String) current;
						values[1] = value;
						rv.put(key, values);
					}

					// if an array is found, extend our current values to include this additional one
					else if (current instanceof String[])
					{
						String[] currentArray = (String[]) current;
						String[] values = new String[currentArray.length + 1];
						System.arraycopy(currentArray, 0, values, 0, currentArray.length);
						values[currentArray.length] = value;
						rv.put(key, values);
					}

					// clean up if a temp file was used
					if (!item.isInMemory())
					{
						item.delete();
					}
				}
				else
				{
//					System.out.println("CDP: file: " + ((DiskFileItem) item).getStoreLocation().getPath() + " : " + item.getFieldName()
//							+ " : inMemory: " + item.isInMemory() + " size: " + item.getSize());

					rv.put(item.getFieldName(), item);
				}
			}
		}
		catch (FileUploadException e)
		{
			M_log.warn("processBody: exception:" + e);
		}
		catch (UnsupportedEncodingException e)
		{
			M_log.warn("processBody: exception:" + e);
		}

		// TODO: add URL parameters

		return rv;
	}

	/**
	 * For any file based parameters, delete the temp. files NOW, not waiting for (eventual, and maybe never) finalization.
	 * 
	 * @param parameters
	 *        The parameters (as parsed by processBody
	 */
	protected void processBodyDone(Map<String, Object> parameters)
	{
		if (parameters == null) return;
		for (Object value : parameters.values())
		{
			if (value instanceof DiskFileItem)
			{
				DiskFileItem dfi = (DiskFileItem) value;
				if (!dfi.isInMemory())
				{
					dfi.delete();
				}
			}
		}
	}

	/**
	 * @return The PubDatesService, via the component manager.
	 */
	protected PubDatesService pubDatesService()
	{
		return (PubDatesService) ComponentManager.get(PubDatesService.class);
	}

	/**
	 * Read a file system file into a byte array
	 * 
	 * @param fileName
	 *        The full filesystem path to the file.
	 * @param fileSize
	 *        The length expected, in bytes.
	 * @return The file data in a byte[]
	 */
	protected byte[] readFile(String fileName, int fileSize)
	{
		File file = new File(fileName);
		try
		{
			byte[] body = new byte[fileSize];
			FileInputStream in = new FileInputStream(file);

			in.read(body);
			in.close();

			return body;
		}
		catch (Throwable t)
		{
			M_log.warn("readFile: " + t);
			return new byte[0];
		}
	}

	/**
	 * @return The SectionService, via the component manager.
	 */
	protected SectionService sectionService()
	{
		return (SectionService) ComponentManager.get(SectionService.class);
	}

	/**
	 * @return The SecurityService, via the component manager.
	 */
	protected SecurityService securityService()
	{
		return (SecurityService) ComponentManager.get(SecurityService.class);
	}

	protected void sendBinaryContent(HttpServletRequest req, HttpServletResponse res, String contentType, String encoding, int len,
			InputStream content) throws ServletException, IOException
	{
		OutputStream out = null;

		try
		{
			if ((encoding != null) && (encoding.length() > 0))
			{
				contentType = contentType + "; charset=" + encoding;
			}
			res.setContentType(contentType);
			// res.addHeader("Content-Disposition", disposition);
			res.setContentLength(len);

			// set the buffer of the response to match what we are reading from the request
			if (len < STREAM_BUFFER_SIZE)
			{
				res.setBufferSize(len);
			}
			else
			{
				res.setBufferSize(STREAM_BUFFER_SIZE);
			}

			out = res.getOutputStream();

			// chunk
			byte[] chunk = new byte[STREAM_BUFFER_SIZE];
			int lenRead;
			while ((lenRead = content.read(chunk)) != -1)
			{
				out.write(chunk, 0, lenRead);
			}
		}
		catch (Throwable e)
		{
			M_log.warn("sendBinaryContent (while streaming, ignoring): " + e);
		}
		finally
		{
			// be a good little program and close the stream - freeing up valuable system resources
			if (content != null)
			{
				content.close();
			}

			if (out != null)
			{
				try
				{
					out.close();
				}
				catch (Throwable ignore)
				{
				}
			}
		}
	}

	/**
	 * Send the requested CHS resource
	 * 
	 * @param req
	 *        request
	 * @param res
	 *        response
	 * @param resourceId
	 *        the CHS resource id to dispatch
	 * @param secure
	 *        if false, bypass normal CHS security
	 * @throws ServletException
	 * @throws IOException
	 */
	protected void sendContent(HttpServletRequest req, HttpServletResponse res, String resourceId, boolean secure) throws ServletException,
			IOException
	{
		if (resourceId == null)
		{
			sendTextContent(req, res, "test/html", "");
			return;
		}

		// get the resource from CHS, bypassing normal security
		ContentResource resource = null;
		try
		{
			if (!secure)
			{
				securityService().pushAdvisor(new SecurityAdvisor()
				{
					public SecurityAdvice isAllowed(String userId, String function, String reference)
					{
						return SecurityAdvice.ALLOWED;
					}
				});
			}

			resource = contentHostingService().getResource(resourceId);
		}
		catch (PermissionException e)
		{
			// M_log.warn("sendContent: " + e);
			res.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}
		catch (IdUnusedException e)
		{
			M_log.warn("sendContent: " + e);
			res.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}
		catch (TypeException e)
		{
			M_log.warn("sendContent: " + e);
			res.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}
		finally
		{
			if (!secure) securityService().popAdvisor();
		}

		int len = resource.getContentLength();
		String contentType = resource.getContentType().toLowerCase();
		String encoding = resource.getProperties().getProperty(ResourceProperties.PROP_CONTENT_ENCODING);

		// for text, we need to do some special handling
		if (contentType.startsWith("text/"))
		{
			// get the content as text
			String contentText = null;
			try
			{
				if (encoding == null) encoding = "UTF-8";
				contentText = new String(resource.getContent(), encoding);
				sendTextContent(req, res, contentType, contentText);
			}
			catch (ServerOverloadException e)
			{
				M_log.warn("sendContent: " + e);
				res.sendError(HttpServletResponse.SC_BAD_REQUEST);
			}
		}

		// for non-text, just send it (stream it in chunks to avoid the elephant-in-snake problem)
		else
		{
			InputStream content = null;
			try
			{
				content = resource.streamContent();
			}
			catch (ServerOverloadException e)
			{
				M_log.warn("sendContent: " + e);
			}

			if (content == null)
			{
				res.sendError(HttpServletResponse.SC_BAD_REQUEST);
			}

			sendBinaryContent(req, res, contentType, encoding, len, content);
		}
	}

	protected void sendErrorHtml(PrintWriter out)
	{
		out.println("<html><head></head></body>There was a problem with this request.</body></html>");
	}

	/**
	 * @return The SearchService, via the component manager.
	 */
	/*
	 * protected SearchService searchService() { return (SearchService) ComponentManager.get(SearchService.class); }
	 */

	@SuppressWarnings("unchecked")
	protected void sendSyllabus(HttpServletRequest req, HttpServletResponse res, String siteId, String userId, boolean pub) throws ServletException,
			IOException
	{
		PrintWriter out = res.getWriter();
		res.setContentType("text/html");

		// check for a defined syllabus
		SyllabusItem syllabusItem = syllabusManager().getSyllabusItemByContextId(siteId);
		if ((syllabusItem != null)
				&& ((hasSize(syllabusManager().getSyllabiForSyllabusItem(syllabusItem))) || (hasLength(syllabusItem.getRedirectURL()))))
		{
			// track
			if (!pub) syllabusManager().trackSyllabusVisitsByUserId(siteId, userId);

			if (hasLength(syllabusItem.getRedirectURL()))
			{
				out.println("<html><head></head><body><a href=\"" + syllabusItem.getRedirectURL()
						+ "\" target=\"_blank\">Read the Syllabus</a></body></html>");
			}
			else
			{
				Set<SyllabusData> syllabiItems = syllabusManager().getSyllabiForSyllabusItem(syllabusItem);
				if (syllabiItems == null)
				{
					out.println("<html><head></head><body>No Syllabus found.</body></html>");
				}
				out.println("<html><head>");
				out.println("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
				out.println("<script type=\"text/javascript\" src=\"/ckeditor/ckeditor/plugins/ckeditor_wiris/core/WIRISplugins.js?viewer=image\" defer=\"defer\"></script>");
				out.println("</head><body>");
				for (SyllabusData sData : syllabiItems)
				{
					// for pub view, only include those marked for the public
					if (pub && (!"yes".equals(sData.getView()))) continue;

					if (sData != null && !sData.getStatus().equals("Draft"))
					{
						String processedBody = accessToCdpDoc(HtmlHelper.clean(sData.getAsset(), true), pub);
						out.println("<h4 style=\"font-size:1em;color:#555;background:#E8E8F0;margin:1em 1em .2em 0;padding:4px 8px 4px 8px;\">"
								+ sData.getTitle() + "</h4>");
						out.println("<div style=\"margin:12px;\">" + processedBody + "</div>");

						// add attachments if any
						Set<SyllabusAttachment> attachments = (Set<SyllabusAttachment>) (syllabusManager()
								.getSyllabusAttachmentsForSyllabusData(sData));
						if (!attachments.isEmpty())
						{
							out.println("<div style=\"margin:12px;\"><h4 style=\"font-size:1em;color:#555;margin:1em 1em .2em 0;\">Attachments</h4><ul>");
							for (SyllabusAttachment attachment : attachments)
							{
								String access = "access";
								if (pub) access = "pub_access";
								String url = "/cdp/doc/" + access + "/content" + attachment.getAttachmentId();
								String description = attachment.getName();
								out.print("<li><a href=\"" + url + "\" target=\"_blank\">" + description + "</a></li>");
							}
							out.println("</ul></div>");
						}
					}
				}

				out.println("</body></html>");
			}
		}
	}

	protected void sendTextContent(HttpServletRequest req, HttpServletResponse res, String contentType, String text) throws ServletException,
			IOException
	{
		// text/url - send a redirect to the URL
		if (contentType.equals("text/url"))
		{
			res.sendRedirect(text);
		}

		// text/anything but html
		else if (!contentType.endsWith("/html"))
		{
			PrintWriter out = res.getWriter();
			res.setContentType("text/html");

			// send it as html in a PRE section
			out.println("<html><head>");
			out.println("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
			out.println("</head><body>");
			out.print("<pre>");
			out.print(text);
			out.println("</pre>");
			out.println("</body></html>");
		}

		// text/html
		else
		{
			PrintWriter out = res.getWriter();
			res.setContentType("text/html");

			// if just a fragment, wrap it into a full document
			boolean fragment = !text.startsWith("<html");
			if (fragment)
			{
				out.println("<html><head>");
				out.println("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
				out.println("<script type=\"text/javascript\" src=\"/ckeditor/ckeditor/plugins/ckeditor_wiris/core/WIRISplugins.js?viewer=image\" defer=\"defer\"></script>");
				out.println("</head><body>");
			}

			out.print(accessToCdpDoc(text, false));

			if (fragment)
			{
				out.println("</body></html>");
			}
		}
	}

	/**
	 * Setup an input stream on a file.
	 * 
	 * @param fileName
	 *        The full filesystem path to the file.
	 * @return An InputStream to read the file, or null if not found.
	 */
	protected InputStream streamFile(String fileName)
	{
		File file = new File(fileName);
		try
		{
			FileInputStream in = new FileInputStream(file);
			return in;
		}
		catch (FileNotFoundException e)
		{
			M_log.warn("streamFile: " + e);
			return null;
		}
	}

	/**
	 * @return The JforumSpecialAccessService, via the component manager.
	 */
	private JForumSpecialAccessService jForumSpecialAccessService()
	{
		return (JForumSpecialAccessService) ComponentManager.get(JForumSpecialAccessService.class);
	}

	/**
	 * @return The PoolService, via the component manager.
	 */
	private PoolService poolService()
	{
		return (PoolService) ComponentManager.get(PoolService.class);
	}

	/**
	 * @return The PresenceService, via the component manager.
	 */
	private PresenceService presenceService()
	{
		return (PresenceService) ComponentManager.get(PresenceService.class);
	}

	/**
	 * @return The ServerConfigurationService, via the component manager.
	 */
	private ServerConfigurationService serverConfigurationService()
	{
		return (ServerConfigurationService) ComponentManager.get(ServerConfigurationService.class);
	}

	/**
	 * @return The SessionManager, via the component manager.
	 */
	private SessionManager sessionManager()
	{
		return (SessionManager) ComponentManager.get(SessionManager.class);
	}

	/**
	 * @return The SiteService, via the component manager.
	 */
	private SiteService siteService()
	{
		return (SiteService) ComponentManager.get(SiteService.class);
	}

	/**
	 * @return The SpecialAccessToolService, via the component manager.
	 */
	private SpecialAccessToolService specialAccessToolService()
	{
		return (SpecialAccessToolService) ComponentManager.get(SpecialAccessToolService.class);
	}

	/**
	 * @return The SubmissionService, via the component manager.
	 */
	private SubmissionService submissionService()
	{
		return (SubmissionService) ComponentManager.get(SubmissionService.class);
	}

	/**
	 * @return The SyllabusManager, via the component manager.
	 */
	private SyllabusManager syllabusManager()
	{
		return (SyllabusManager) ComponentManager.get(SyllabusManager.class);
	}

	/**
	 * @return The ThreadLocalManager, via the component manager.
	 */
	private ThreadLocalManager threadLocalManager()
	{
		return (ThreadLocalManager) ComponentManager.get(ThreadLocalManager.class);
	}

	/**
	 * @return The TimeService, via the component manager.
	 */
	private TimeService timeService()
	{
		return (TimeService) ComponentManager.get(TimeService.class);
	}

	/**
	 * @return The UserDirectoryService, via the component manager.
	 */
	private UserDirectoryService userDirectoryService()
	{
		return (UserDirectoryService) ComponentManager.get(UserDirectoryService.class);
	}
}
