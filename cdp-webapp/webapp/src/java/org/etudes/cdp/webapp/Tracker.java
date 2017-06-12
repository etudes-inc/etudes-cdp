/**********************************************************************************
 * $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-webapp/webapp/src/java/org/etudes/cdp/webapp/Tracker.java $
 * $Id: Tracker.java 8233 2014-06-11 18:59:59Z ggolden $
 ***********************************************************************************
 *
 * Copyright (c) 2012 Etudes, Inc.
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

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sakaiproject.component.api.ServerConfigurationService;
import org.sakaiproject.component.cover.ComponentManager;
import org.sakaiproject.db.api.SqlService;
import org.sakaiproject.db.api.SqlServiceDeadlockException;
import org.sakaiproject.event.api.EventTrackingService;
import org.sakaiproject.event.api.UsageSession;
import org.sakaiproject.event.api.UsageSessionService;
import org.sakaiproject.exception.IdUnusedException;
import org.sakaiproject.id.api.IdManager;
import org.sakaiproject.presence.api.PresenceService;
import org.sakaiproject.site.api.Site;
import org.sakaiproject.site.api.SiteService;
import org.sakaiproject.site.api.ToolConfiguration;
import org.sakaiproject.thread_local.api.ThreadLocalManager;
import org.sakaiproject.time.api.Time;
import org.sakaiproject.time.api.TimeService;
import org.sakaiproject.tool.api.ContextSession;
import org.sakaiproject.tool.api.Session;
import org.sakaiproject.tool.cover.SessionManager;
import org.sakaiproject.util.StringUtil;

/**
 * Tracker ...<br />
 */
public class Tracker implements Runnable
{
	class UsageSessionIdImpl implements UsageSession
	{
		protected Tracker tracker = null;
		protected String userId = null;

		public UsageSessionIdImpl(String userId, Tracker tracker)
		{
			this.userId = userId;
			this.tracker = tracker;
		}

		public int compareTo(Object arg0)
		{
			return 0;
		}

		public String getBrowserId()
		{
			return null;
		}

		public Time getEnd()
		{
			return null;
		}

		public String getId()
		{
			String sessionId = this.tracker.getUserSession(this.userId);

			return sessionId;
		}

		public String getIpAddress()
		{
			return null;
		}

		public String getServer()
		{
			return null;
		}

		public Time getStart()
		{
			return null;
		}

		public String getUserAgent()
		{
			return null;
		}

		public String getUserDisplayId()
		{
			return null;
		}

		public String getUserEid()
		{
			return null;
		}

		public String getUserId()
		{
			return this.userId;
		}

		public boolean isClosed()
		{
			return false;
		}
	}

	/** Our log. */
	private static Log M_log = LogFactory.getLog(Tracker.class);

	/** # ms of "not seen" to consider a user timed out of a chat presence (1 minutes * 60 seconds/minute * 1000 ms/second). */
	protected static long CHAT_PRESENCE_THRESHOLD = 1 * 60 * 1000;

	/** # ms of "not seen" to consider a user timed out of a presence (30 minutes * 60 seconds/minute * 1000 ms/second). */
	protected static long PRESENCE_THRESHOLD = 30 * 60 * 1000;

	/** # ms of "not seen" to consider a user timed out of a session (30 minutes * 60 seconds/minute * 1000 ms/second). */
	protected static long SESSION_THRESHOLD = 30 * 60 * 1000;

	/** Configuration: to run the ddl on init or not. */
	protected boolean autoDdl = false;

	/** The checker thread. */
	protected Thread checkerThread = null;

	/** Are we clustered? */
	protected boolean clustered = false;

	/** Map of userId + presenceId -> last seen time stamp. */
	protected Map<String, Date> recentChatPresence = new HashMap<String, Date>();

	/** Map of userId + presenceId -> last seen time stamp. */
	protected Map<String, Date> recentPresence = new HashMap<String, Date>();

	/** Map of userId -> last seen time stamp. */
	protected Map<String, Date> recentUsers = new HashMap<String, Date>();

	/** Map of sessionId -> siteId set to track that the site was visited in the session. */
	protected Map<String, Set<String>> sessionVisits = new HashMap<String, Set<String>>();

	/** The thread quit flag. */
	protected boolean threadStop = false;

	/** How long to wait (ms) between checks. */
	protected long timeoutCheckMs = 30 * 1000;

	/** Map of userId -> session id. */
	protected Map<String, String> userSessions = new HashMap<String, String>();

	/**
	 * Construct, starting the maintenance thread.
	 * 
	 * @param clustered
	 *        if true, setup to work in a clustered environment, otherwise, work as the single stand-alone app server.
	 */
	public Tracker(boolean clustered)
	{
		this.clustered = clustered;

		// if clustered, we have some database to deal with
		if (this.clustered)
		{
			String str = serverConfigurationService().getString("auto.ddl");
			if (str != null) this.autoDdl = Boolean.valueOf(str).booleanValue();
			M_log.info("CDP Tracker: auto.ddl: " + this.autoDdl);

			// if we are auto-creating our schema, check and create
			if (this.autoDdl)
			{
				sqlService().ddl(this.getClass().getClassLoader(), "tracker");
			}
		}

		// start the checking thread
		if (this.timeoutCheckMs > 0)
		{
			start();
		}
	}

	/**
	 * Stop the maintenance thread, deal with any remaining users.
	 */
	public void destroy()
	{
		stop();

		// timeout all presence
		Set<String> timedOutPresence = new HashSet<String>();
		synchronized (this.recentPresence)
		{
			for (Map.Entry<String, Date> entry : this.recentPresence.entrySet())
			{
				timedOutPresence.add(entry.getKey());
			}
		}
		synchronized (this.recentChatPresence)
		{
			for (Map.Entry<String, Date> entry : this.recentChatPresence.entrySet())
			{
				timedOutPresence.add(entry.getKey());
			}
		}
		for (String presence : timedOutPresence)
		{
			processTimedOutPresence(presence);

			// threadLocal may contain user (based on presence) specific information
			threadLocalManager().clear();
		}

		// collect all remaining users
		Set<String> timedOut = new HashSet<String>();
		synchronized (this.recentUsers)
		{
			for (Map.Entry<String, Date> entry : this.recentUsers.entrySet())
			{
				timedOut.add(entry.getKey());
			}
		}

		// process
		for (String userId : timedOut)
		{
			processTimedOutUser(userId);

			// threadLocal may contain user specific information
			threadLocalManager().clear();
		}
	}

	/**
	 * Return the established session for this user.
	 * 
	 * @param userId
	 *        The user id.
	 * @return The user's session id, or null if there is none.s
	 */
	public String getUserSession(String userId)
	{
		return this.userSessions.get(userId);
	}

	/**
	 * Run the expiration checking thread.
	 */
	public void run()
	{
		// TODO: ? do we need to ? -ggolden
		// since we might be running while the component manager is still being created and populated,
		// such as at server startup, wait here for a complete component manager
		// ComponentManager.waitTillConfigured();

		// loop till told to stop
		while ((!this.threadStop) && (!Thread.currentThread().isInterrupted()))
		{
			if (M_log.isDebugEnabled()) M_log.debug("run: running");

			// collect timed out users
			Set<String> timedOut = new HashSet<String>();

			// compute a time in the past, before which we consider last-seen dates to be too old, so timeout the user
			Date sessionThreshold = new Date(System.currentTimeMillis() - SESSION_THRESHOLD);
			Date presenceThreshold = new Date(System.currentTimeMillis() - PRESENCE_THRESHOLD);
			Date chatPresenceThreshold = new Date(System.currentTimeMillis() - CHAT_PRESENCE_THRESHOLD);

			// check the known users for any timed out
			synchronized (this.recentUsers)
			{
				for (Map.Entry<String, Date> entry : this.recentUsers.entrySet())
				{
					if (entry.getValue().before(sessionThreshold))
					{
						// timeout! save userId for processing
						timedOut.add(entry.getKey());
					}
				}
			}

			// collect timed out presence, also presence from users with timed out sessions
			Set<String> timedOutPresence = new HashSet<String>();

			// check the presence for timeout
			synchronized (this.recentPresence)
			{
				for (Map.Entry<String, Date> entry : this.recentPresence.entrySet())
				{
					if (entry.getValue().before(presenceThreshold))
					{
						// timeout! save userId for processing
						timedOutPresence.add(entry.getKey());
					}

					// TODO: maybe we don't - could a presence be established (thus extending session) and then lost before the session (much longer timeout) expires?
					else
					{
						// first part is user id
						String[] parts = StringUtil.splitFirst(entry.getKey(), "|");
						if (timedOut.contains(parts[0]))
						{
							// this user has timed out session, timeout their presence too
							timedOutPresence.add(entry.getKey());
						}
					}
				}
			}

			// these timeout faster
			synchronized (this.recentChatPresence)
			{
				for (Map.Entry<String, Date> entry : this.recentChatPresence.entrySet())
				{
					if (entry.getValue().before(chatPresenceThreshold))
					{
						// timeout! save userId for processing
						timedOutPresence.add(entry.getKey());
					}

					// TODO: maybe we don't - could a presence be established (thus extending session) and then lost before the session (much longer timeout) expires?
					else
					{
						// first part is user id
						String[] parts = StringUtil.splitFirst(entry.getKey(), "|");
						if (timedOut.contains(parts[0]))
						{
							// this user has timed out session, timeout their presence too
							timedOutPresence.add(entry.getKey());
						}
					}
				}
			}

			// process any presence we found
			for (String presence : timedOutPresence)
			{
				processTimedOutPresence(presence);

				// threadLocal may contain user (based on presence) specific information
				threadLocalManager().clear();
			}

			// process any users we found
			for (String userId : timedOut)
			{
				processTimedOutUser(userId);

				// threadLocal may contain user specific information
				threadLocalManager().clear();
			}

			// take a small nap
			try
			{
				Thread.sleep(timeoutCheckMs);
			}
			catch (Exception ignore)
			{
			}
		}
	}

	/**
	 * Setup some Sakai Session and UsageSession information to work with the existing mechanisms
	 * 
	 * @param userId
	 *        The user id.
	 * @param siteId
	 *        The site id.
	 * @return true if a fake session was setup, false if not.
	 */
	public boolean setupFakeSession(String userId, String siteId)
	{
		// if we have a real session with a user, no faking
		if (SessionManager.getCurrentSessionUserId() != null) return false;

		// set this user as the current user
		Session s = SessionManager.getCurrentSession();
		s.setUserId(userId);

		// setup a UsageSession that just can return the user and session ids, so UsageSessionService.getSessioId() works
		// (important for events created by a CDP call)
		UsageSession us = new UsageSessionIdImpl(userId, this);
		s.setAttribute(UsageSessionService.USAGE_SESSION_KEY, us);

		if (siteId != null)
		{
			// make sure there's a flag in the site's (context) session in the session
			// to stop the SiteVisitServiceImpl from registering a visit.
			ContextSession cs = s.getContextSession(siteId);
			cs.setAttribute("AM-VISITED", Boolean.TRUE);
		}
		
		return true;
	}

	/**
	 * Extend or establish a user's presence in a site's chat.<br />
	 * Assume trackUser() is called first.
	 * 
	 * @param userId
	 *        The user id.
	 * @param siteId
	 *        The site id.
	 */
	public void trackChatPresence(String userId, String siteId, String room)
	{
		// the presence location is the site's chat tool id
		Site site = null;
		try
		{
			site = siteService().getSite(siteId);
		}
		catch (IdUnusedException e)
		{
			return;
		}
		ToolConfiguration chatTool = site.getToolForCommonId("sakai.chat");
		if (chatTool == null) return;

		String presenceId = chatTool.getId() + "|" + room;

		// our map combines user and presence ids for the key
		String key = userId + "|" + presenceId;

		// do we know this user + site here already?
		// either way, make an (updated) entry for the user
		boolean known = false;
		synchronized (this.recentChatPresence)
		{
			known = (this.recentChatPresence.get(key) != null);
			this.recentChatPresence.put(key, new Date());
		}

		// if new here, deal with a possible new user presence
		boolean success = true;
		if (!known)
		{
			success = processNewlySeenPresence(userId, presenceId, null);
		}
	}

	/**
	 * Extend or establish a user's presence in a site.<br />
	 * Assume trackUser() is called first.
	 * 
	 * @param userId
	 *        The user id.
	 * @param siteId
	 *        The site id.
	 */
	public void trackSitePresence(String userId, String siteId)
	{
		// the presence location is "<site id>-presence"
		String presenceId = siteId + "-presence";

		// our map combines user and presence ids for the key
		String key = userId + "|" + presenceId;

		// do we know this user + site here already?
		// either way, make an (updated) entry for the user
		boolean known = false;
		synchronized (this.recentPresence)
		{
			known = (this.recentPresence.get(key) != null);
			this.recentPresence.put(key, new Date());
		}

		// if new here, deal with a possible new user presence
		boolean success = true;
		if (!known)
		{
			success = processNewlySeenPresence(userId, presenceId, siteId);
		}

		// if we failed to get the newly seen user processed, forget the user
		// if (!success)
		// {
		// // record this time as this user's last seen time
		// synchronized (this.recentUsers)
		// {
		// this.recentUsers.remove(userId);
		// }
		// }
	}

	/**
	 * Extend or establish the user's session
	 * 
	 * @param userId
	 *        The user id.
	 * @param ip
	 *        The remote IP address.
	 * @param agent
	 *        The user agent.
	 */
	public void trackUser(String userId, String ip, String agent)
	{
		// do we know this user already?
		// either way, make an (updated) entry for the user
		boolean known = false;
		synchronized (this.recentUsers)
		{
			known = (this.recentUsers.get(userId) != null);
			this.recentUsers.put(userId, new Date());
		}

		// if new here, deal with a possible new user session
		boolean success = true;
		if (!known)
		{
			success = processNewlySeenUser(userId, ip, agent);
		}

		// if we failed to get the newly seen user processed, forget the user
		if (!success)
		{
			// record this time as this user's last seen time
			synchronized (this.recentUsers)
			{
				this.recentUsers.remove(userId);
			}
		}
	}

	/**
	 * @return The EventTrackingService, via the component manager.
	 */
	protected EventTrackingService eventTrackingService()
	{
		return (EventTrackingService) ComponentManager.get(EventTrackingService.class);
	}

	/**
	 * @return The IdManager, via the component manager.
	 */
	protected IdManager idManager()
	{
		return (IdManager) ComponentManager.get(IdManager.class);
	}

	/**
	 * @return The PresenceService, via the component manager.
	 */
	protected PresenceService presenceService()
	{
		return (PresenceService) ComponentManager.get(PresenceService.class);
	}

	/**
	 * Check if this user has this presence already, and if not, establish one.
	 * 
	 * @param userId
	 *        The user id.
	 * @param presenceId
	 *        The presence location.
	 * @param siteId
	 *        If this presence is site-level, the site id.
	 */
	protected boolean processNewlySeenPresence(final String userId, final String presenceId, final String siteId)
	{
		// all in a transaction, repeated if we have to bail out
		// to deal with multiple app servers doing this concurrently for the same user, we want only one Session record.
		// add a new session for the user if needed
		// record that the user has been seen here
		try
		{
			sqlService().transact(new Runnable()
			{
				public void run()
				{
					processNewlySeenPresenceTx(userId, presenceId, siteId);
				}
			}, "processNewlySeenPresence: " + userId);
		}
		catch (SqlServiceDeadlockException e)
		{
			M_log.warn("processNewlySeenPresence: tx failed for user: " + userId);
			return false;
		}

		return true;
	}

	/**
	 * 
	 * @param userId
	 *        The user id.
	 * @param presenceId
	 *        The presence location.
	 * @param siteId
	 *        If this presence is site-level, the site id.
	 */
	protected void processNewlySeenPresenceTx(String userId, String presenceId, String siteId)
	{
		// does any app server see this user presence? - if not clustered, the answer is no
		boolean seenByOthers = false;
		if (this.clustered)
		{
			String sql = "SELECT SERVER_ID FROM TRACKER_PRESENCE_SERVER WHERE USER_ID = ? AND PRESENCE_ID = ?";
			Object[] fields = new Object[2];
			fields[0] = userId;
			fields[1] = presenceId;
			List servers = sqlService().dbRead(sql, fields, null);
			seenByOthers = !servers.isEmpty();
		}

		if (!seenByOthers)
		{
			// create a presence for this session / location
			String sessionId = this.userSessions.get(userId);

			// TODO: will this fail if we already have presence for session? hope so!
			String sql = "INSERT INTO SAKAI_PRESENCE (SESSION_ID, LOCATION_ID) VALUES (?,?)";
			Object[] fields = new Object[2];
			fields[0] = sessionId;
			fields[1] = presenceId;
			boolean success = sqlService().dbWrite(sql, fields);

			// presence event
			eventTrackingService().post(
					eventTrackingService().newEvent(PresenceService.EVENT_PRESENCE, presenceService().presenceReference(presenceId), true));

			// if this fails, it may be due to a unique key violation on SAKAI_PRESENCE, meaning there *is* a presence there for this user already
			// the throw will cause the transaction to rollback and be retried
			if (!success) throw new SqlServiceDeadlockException(null);

			if (siteId != null)
			{
				// see if we can record a site visit for this session - will fail if we have one already
				if (this.clustered)
				{
					sql = "INSERT INTO TRACKER_SESSION_VISIT (SESSION_ID, SITE_ID) VALUES (?,?)";
					fields = new Object[2];
					fields[0] = sessionId;
					fields[1] = siteId;
					success = sqlService().dbWrite(sql, fields);
				}
				else
				{
					// make sure we have not already recorded a site visit for this session
					synchronized (this.sessionVisits)
					{
						Set<String> visits = this.sessionVisits.get(sessionId);
						if (visits == null)
						{
							visits = new HashSet<String>();
							this.sessionVisits.put(sessionId, visits);
						}

						if (visits.contains(siteId))
						{
							success = false;
						}
						else
						{
							success = true;
							visits.add(siteId);
						}
					}
				}

				// if we failed, then we have already registered a visit for this session
				// otherwise, we want to do so here
				if (success)
				{
					// as of now
					Long visitTime = System.currentTimeMillis();

					// we try an insert - this will fail if the user has ever been to this site before
					sql = "INSERT INTO AM_SITE_VISIT (CONTEXT, USER_ID, FIRST_VISIT, LAST_VISIT, VISITS) VALUES (?,?,?,?,?)";
					fields = new Object[5];
					fields[0] = siteId;
					fields[1] = userId;
					fields[2] = visitTime;
					fields[3] = visitTime;
					fields[4] = 1;
					success = sqlService().dbWrite(sql, fields);

					// if we fail, we need to update
					if (!success)
					{
						sql = "UPDATE AM_SITE_VISIT SET LAST_VISIT=?, VISITS=VISITS+1 WHERE CONTEXT=? AND USER_ID=?";
						fields = new Object[3];
						fields[0] = visitTime;
						fields[1] = siteId;
						fields[2] = userId;
						sqlService().dbWrite(sql, fields);
					}
				}
			}
		}

		// record the user's presence seen here
		if (this.clustered)
		{
			String sql = "INSERT INTO TRACKER_PRESENCE_SERVER (USER_ID, PRESENCE_ID, SERVER_ID) VALUES (?,?,?)";
			Object[] fields = new Object[3];
			fields[0] = userId;
			fields[1] = presenceId;
			fields[2] = serverConfigurationService().getServerIdInstance();
			sqlService().dbWrite(sql, fields);
		}
	}

	/**
	 * Check if this user has a session already, and if not, establish one.
	 * 
	 * @param userId
	 *        The user id.
	 * @param ip
	 *        The remote IP address.
	 * @param agent
	 *        The user agent.
	 */
	protected boolean processNewlySeenUser(final String userId, final String ip, final String agent)
	{
		// all in a transaction, repeated if we have to bail out
		// to deal with multiple app servers doing this concurrently for the same user, we want only one Session record.
		// add a new session for the user if needed
		// record that the user has been seen here
		try
		{
			sqlService().transact(new Runnable()
			{
				public void run()
				{
					processNewlySeenUserTx(userId, ip, agent);
				}
			}, "processNewlySeenUser: " + userId);
		}
		catch (SqlServiceDeadlockException e)
		{
			M_log.warn("processNewlySeenUser: tx failed for user: " + userId);
			return false;
		}

		return true;
	}

	/**
	 * 
	 * @param userId
	 *        The user id.
	 * @param ip
	 *        The remote IP address.
	 * @param agent
	 *        The user agent.
	 */
	protected void processNewlySeenUserTx(String userId, String ip, String agent)
	{
		Time now = timeService().newTime();

		// find an active session for the user (or none) - if not clustered, there is no session
		String sessionId = null;
		if (this.clustered)
		{
			String sql = "SELECT SESSION_ID FROM TRACKER_USER_SESSION WHERE USER_ID = ?";
			Object[] fields = new Object[1];
			fields[0] = userId;
			List sessions = sqlService().dbRead(sql, fields, null);
			if (!sessions.isEmpty()) sessionId = (String) sessions.get(0);
		}

		// if we have no session, make one
		boolean needToLog = false;
		if (sessionId == null)
		{
			// create a new session for the user, getting back the session id
			sessionId = idManager().createUuid();

			String sql = "INSERT INTO SAKAI_SESSION (SESSION_ID,SESSION_SERVER,SESSION_USER,SESSION_IP,SESSION_USER_AGENT,SESSION_START,SESSION_END) VALUES (?, ?, ?, ?, ?, ?, ?)";
			Object[] fields = new Object[7];
			fields[0] = sessionId;
			fields[1] = serverConfigurationService().getServerIdInstance();
			fields[2] = userId;
			fields[3] = ip;
			fields[4] = agent;
			fields[5] = now;
			fields[6] = now;
			sqlService().dbWrite(sql, fields);

			// we need to make a login event, but after we record the session id
			needToLog = true;

			// record the user's session
			if (this.clustered)
			{
				sql = "INSERT INTO TRACKER_USER_SESSION (USER_ID, SESSION_ID) VALUES (?,?)";
				fields = new Object[2];
				fields[0] = userId;
				fields[1] = sessionId;
				boolean success = sqlService().dbWrite(sql, fields);

				// if this fails, it may be due to a unique key violation on user_id, meaning there *is* a session for this user already
				// the throw will cause the transaction to rollback and be retried
				if (!success) throw new SqlServiceDeadlockException(null);
			}
		}

		// record user's session internally
		synchronized (this.userSessions)
		{
			this.userSessions.put(userId, sessionId);
		}

		// now that we know the session id, we can log
		if (needToLog)
		{
			// login event
			eventTrackingService().post(eventTrackingService().newEvent(UsageSessionService.EVENT_LOGIN, "inTouch", true));
		}

		// record the user's presence here
		if (this.clustered)
		{
			String sql = "INSERT INTO TRACKER_USER_SERVER (USER_ID, SERVER_ID) VALUES (?,?)";
			Object[] fields = new Object[2];
			fields[0] = userId;
			fields[1] = serverConfigurationService().getServerIdInstance();
			sqlService().dbWrite(sql, fields);
		}

		// record the user in our tracking table
		// for a new user, insert (for known users this will fail)
		String sql = "INSERT INTO TRACKER_USER_TRACKING (USER_ID, FIRST_VISIT, LAST_VISIT, VISITS) VALUES (?,?,?,?)";
		Object[] fields = new Object[4];
		fields[0] = userId;
		fields[1] = now;
		fields[2] = now;
		fields[3] = Integer.valueOf(1);
		boolean success = sqlService().dbWrite(sql, fields);

		// for a return user, do the update
		if (!success)
		{
			sql = "UPDATE TRACKER_USER_TRACKING SET LAST_VISIT = ?, VISITS = VISITS+1 WHERE USER_ID = ?";
			fields = new Object[2];
			fields[0] = now;
			fields[1] = userId;
			sqlService().dbWrite(sql, fields);
		}
	}

	protected void processTimedOutPresence(String key)
	{
		// first part is user id, second is presence id
		String[] parts = StringUtil.splitFirst(key, "|");
		final String userId = parts[0];
		final String presenceId = parts[1];

		// on the maintenance thread, so no fake info setup for the user
		setupFakeSession(userId, null);

		// remove user from our map (it may be in either one)
		synchronized (this.recentPresence)
		{
			this.recentPresence.remove(key);
		}
		synchronized (this.recentChatPresence)
		{
			this.recentChatPresence.remove(key);
		}

		sqlService().transact(new Runnable()
		{
			public void run()
			{
				processTimedOutPresenceTx(userId, presenceId);
			}
		}, "processTimedOutPresence: " + key);
	}

	/**
	 * 
	 * @param userId
	 *        The user id.
	 */
	protected void processTimedOutPresenceTx(String userId, String presenceId)
	{
		// remove the record from the presence_server table
		if (this.clustered)
		{
			String sql = "DELETE FROM TRACKER_PRESENCE_SERVER WHERE USER_ID = ? AND PRESENCE_ID = ? AND SERVER_ID = ?";
			Object[] fields = new Object[3];
			fields[0] = userId;
			fields[1] = presenceId;
			fields[2] = serverConfigurationService().getServerIdInstance();
			sqlService().dbWrite(sql, fields);
		}

		// any remaining entries for this user at this location?
		boolean seenByOthers = false;
		if (this.clustered)
		{
			String sql = "SELECT SERVER_ID FROM TRACKER_PRESENCE_SERVER WHERE USER_ID = ? and PRESENCE_ID = ?";
			Object[] fields = new Object[2];
			fields[0] = userId;
			fields[1] = presenceId;
			List servers = sqlService().dbRead(sql, fields, null);
			seenByOthers = !servers.isEmpty();
		}

		// if nobody has this user there anymore, close the user's presence
		if (!seenByOthers)
		{
			// get the session id
			String sessionId = this.userSessions.get(userId);

			// remove the presence
			String sql = "DELETE FROM SAKAI_PRESENCE WHERE SESSION_ID = ? AND LOCATION_ID = ?";
			Object[] fields = new Object[2];
			fields[0] = sessionId;
			fields[1] = presenceId;
			sqlService().dbWrite(sql, fields);

			// presence event
			eventTrackingService().post(
					eventTrackingService().newEvent(PresenceService.EVENT_ABSENCE, presenceService().presenceReference(presenceId), true));
		}
	}

	protected void processTimedOutUser(final String userId)
	{
		// on the maintenance thread, so no fake info setup for the user
		setupFakeSession(userId, null);

		// remove user from knownUsers
		synchronized (this.recentUsers)
		{
			this.recentUsers.remove(userId);
		}

		sqlService().transact(new Runnable()
		{
			public void run()
			{
				processTimedOutUserTx(userId);
			}
		}, "processTimedOutUser: " + userId);
	}

	/**
	 * 
	 * @param userId
	 *        The user id.
	 */
	protected void processTimedOutUserTx(String userId)
	{
		// remove the record from the user_server table
		if (this.clustered)
		{
			String sql = "DELETE FROM TRACKER_USER_SERVER WHERE USER_ID = ? AND SERVER_ID = ?";
			Object[] fields = new Object[2];
			fields[0] = userId;
			fields[1] = serverConfigurationService().getServerIdInstance();
			sqlService().dbWrite(sql, fields);
		}

		// any remaining entries for this user?
		boolean seenByOthers = false;
		if (this.clustered)
		{
			String sql = "SELECT SERVER_ID FROM TRACKER_USER_SERVER WHERE USER_ID = ?";
			Object[] fields = new Object[1];
			fields[0] = userId;
			List servers = sqlService().dbRead(sql, fields, null);
			seenByOthers = !servers.isEmpty();
		}

		// if nobody has this user anymore, close the user's session
		if (!seenByOthers)
		{
			// get the session id
			String sessionId = this.userSessions.get(userId);

			// remove from our session table
			if (this.clustered)
			{
				String sql = "DELETE FROM TRACKER_USER_SESSION WHERE USER_ID = ?";
				Object[] fields = new Object[1];
				fields[0] = userId;
				sqlService().dbWrite(sql, fields);
			}

			// logout event (do this before we loose the internal session id)
			eventTrackingService().post(eventTrackingService().newEvent("auto.logout", null, true));

			// remove internally
			synchronized (this.userSessions)
			{
				this.userSessions.remove(userId);
			}

			// close the session
			String sql = "UPDATE SAKAI_SESSION SET SESSION_END = ? WHERE SESSION_ID = ?";
			Object[] fields = new Object[2];
			fields[0] = timeService().newTime();
			fields[1] = sessionId;
			sqlService().dbWrite(sql, fields);

			// remove the site visit notes for this session
			if (this.clustered)
			{
				sql = "DELETE FROM TRACKER_SESSION_VISIT WHERE SESSION_ID = ?";
				fields = new Object[1];
				fields[0] = sessionId;
				sqlService().dbWrite(sql, fields);
			}
		}
	}

	/**
	 * @return The ServerConfigurationService, via the component manager.
	 */
	protected ServerConfigurationService serverConfigurationService()
	{
		return (ServerConfigurationService) ComponentManager.get(ServerConfigurationService.class);
	}

	/**
	 * @return The SiteService, via the component manager.
	 */
	protected SiteService siteService()
	{
		return (SiteService) ComponentManager.get(SiteService.class);
	}

	/**
	 * @return The SqlService, via the component manager.
	 */
	protected SqlService sqlService()
	{
		return (SqlService) ComponentManager.get(SqlService.class);
	}

	/**
	 * Start the clean and report thread.
	 */
	protected void start()
	{
		this.threadStop = false;

		this.checkerThread = new Thread(this, getClass().getName());
		this.checkerThread.start();
	}

	/**
	 * Stop the clean and report thread.
	 */
	protected void stop()
	{
		if (this.checkerThread == null) return;

		// signal the thread to stop
		this.threadStop = true;

		// wake up the thread
		this.checkerThread.interrupt();

		this.checkerThread = null;
	}

	/**
	 * @return The ThreadLocalManager, via the component manager.
	 */
	protected ThreadLocalManager threadLocalManager()
	{
		return (ThreadLocalManager) ComponentManager.get(ThreadLocalManager.class);
	}

	/**
	 * @return The TimeService, via the component manager.
	 */
	protected TimeService timeService()
	{
		return (TimeService) ComponentManager.get(TimeService.class);
	}
}
