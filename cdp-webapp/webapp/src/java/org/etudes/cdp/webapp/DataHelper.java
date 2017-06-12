/**********************************************************************************
 * $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-webapp/webapp/src/java/org/etudes/cdp/webapp/DataHelper.java $
 * $Id: DataHelper.java 6839 2013-12-23 22:57:00Z ggolden $
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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sakaiproject.component.cover.ComponentManager;
import org.sakaiproject.db.api.SqlReader;
import org.sakaiproject.db.api.SqlService;

/**
 * DataHelper helps CDP get some data.
 */
public class DataHelper
{
	/** Our log. */
	private static Log M_log = LogFactory.getLog(DataHelper.class);

	/**
	 * Count how many active students in the site have not visited in the last period (days).
	 * 
	 * @param siteId
	 *        The site id.
	 * @param period
	 *        The period in days.
	 * @return The # not visited.
	 */
	public int getSiteStudentNotVisitedInPeriod(String siteId, int period)
	{
		// Note: This will only work with "Student" role users - not "access" or any other role names.

		// compute the cutoff date for "recent" (based on 7 day period)
		Calendar cutoff = Calendar.getInstance();
		cutoff.add(Calendar.DATE, -1 * period);
		final Date cutoffDate = cutoff.getTime();

		// get a last visit date for all the active "Student" role users in the site
		// Note: joining to the sakai_user table eliminates any grants to user ids which have been since deleted but left in the grants table
		StringBuilder sql = new StringBuilder();
		sql.append("SELECT G.USER_ID, A.LAST_VISIT FROM SAKAI_REALM_RL_GR G ");
		sql.append("LEFT OUTER JOIN AM_SITE_VISIT A ON G.USER_ID=A.USER_ID AND A.CONTEXT=? ");
		sql.append("JOIN SAKAI_REALM R ON G.REALM_KEY=R.REALM_KEY ");
		sql.append("JOIN SAKAI_REALM_ROLE O ON G.ROLE_KEY=O.ROLE_KEY ");
		sql.append("JOIN SAKAI_USER U ON G.USER_ID=U.USER_ID ");
		sql.append("WHERE R.REALM_ID=? AND G.ACTIVE=1 AND O.ROLE_NAME='Student'");

		Object[] fields = new Object[2];
		fields[0] = siteId;
		fields[1] = "/site/" + siteId;

		@SuppressWarnings("rawtypes")
		List results = sqlService().dbRead(sql.toString(), fields, new SqlReader()
		{
			public Object readSqlResultRecord(ResultSet result)
			{
				try
				{
					String userId = sqlService().readString(result, 1);
					Date lastVisit = sqlService().readDate(result, 2);

					// if this user has never visited, or visited before the cutoff, add it to the return
					if ((lastVisit == null) || (lastVisit.before(cutoffDate)))
					{
						return userId;
					}
					return null;
				}
				catch (SQLException e)
				{
					M_log.warn("getSiteStudentNotVisitedInPeriod: " + e);
					return null;
				}
			}
		});

		// count the users
		return results.size();
	}

	public Map<String, Integer> getUserUnreadPmCounts(String userId)
	{
		final Map<String, Integer> rv = new HashMap<String, Integer>();

		String sql = "SELECT S.COURSE_ID, COUNT(1) FROM JFORUM_PRIVMSGS M" + " JOIN JFORUM_USERS U ON M.PRIVMSGS_TO_USERID = U.USER_ID"
				+ " JOIN JFORUM_SAKAI_COURSE_PRIVMSGS S ON M.PRIVMSGS_ID = S.PRIVMSGS_ID" + " WHERE PRIVMSGS_TYPE = 1 AND U.SAKAI_USER_ID = ?"
				+ " GROUP BY S.COURSE_ID;";
		Object[] fields = new Object[1];
		fields[0] = userId;

		sqlService().dbRead(sql.toString(), fields, new SqlReader()
		{
			public Object readSqlResultRecord(ResultSet result)
			{
				try
				{
					String siteId = sqlService().readString(result, 1);
					Integer count = sqlService().readInteger(result, 2);

					rv.put(siteId, count);

					return null;
				}
				catch (SQLException e)
				{
					M_log.warn("getUserUnreadPmCounts: " + e);
					return null;
				}
			}
		});

		return rv;
	}

	/**
	 * @return The SqlService, via the component manager.
	 */
	protected SqlService sqlService()
	{
		return (SqlService) ComponentManager.get(SqlService.class);
	}
}
