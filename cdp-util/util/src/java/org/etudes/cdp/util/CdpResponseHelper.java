/**********************************************************************************
 * $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-util/util/src/java/org/etudes/cdp/util/CdpResponseHelper.java $
 * $Id: CdpResponseHelper.java 9226 2014-11-18 03:25:24Z ggolden $
 ***********************************************************************************
 *
 * Copyright (c) 2013, 2014 Etudes, Inc.
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

package org.etudes.cdp.util;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.etudes.util.DateHelper;
import org.sakaiproject.component.api.ServerConfigurationService;
import org.sakaiproject.component.cover.ComponentManager;
import org.sakaiproject.time.api.Time;
import org.sakaiproject.time.api.TimeRange;
import org.sakaiproject.time.cover.TimeService;

/**
 * CourseMapItemType ...
 */
public class CdpResponseHelper
{
	/**
	 * Replace any access references in src or href attributes of tags with cdp/doc references
	 * 
	 * @param text
	 * @return The converted text.
	 */
	public static String accessToCdpDoc(String text, boolean pub)
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

	/**
	 * 
	 * @param timeMs
	 * @return [0]=year (~2013) [1]=month (~1..12) [2]=day (~1..31) [3]=hour (~0..23) [4]=minute (~0..59) [5]=second (~0..59)
	 */
	public static String[] dateBreakdownInUserZone(long timeMs)
	{
		// use the end-user's locale and time zone prefs
		// Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		java.util.Calendar calendar = java.util.Calendar.getInstance();
		calendar.setTimeZone(userZone);
		calendar.setTimeInMillis(timeMs);

		String[] rv = new String[6];

		// ~2013
		int year = calendar.get(java.util.Calendar.YEAR);
		rv[0] = Integer.toString(year);

		// ~ 0 .. 11
		int month = calendar.get(java.util.Calendar.MONTH);
		rv[1] = twoDigits(month + 1);

		// ~1 .. 31
		int day = calendar.get(java.util.Calendar.DAY_OF_MONTH);
		rv[2] = twoDigits(day);

		// ~0 .. 23
		int hour = calendar.get(java.util.Calendar.HOUR_OF_DAY);
		rv[3] = twoDigits(hour);

		// ~0 .. 59
		int minute = calendar.get(java.util.Calendar.MINUTE);
		rv[4] = twoDigits(minute);

		// ~0 .. 59
		int second = calendar.get(java.util.Calendar.SECOND);
		rv[5] = twoDigits(second);

		return rv;
	}

	/**
	 * @return date formatted for the user's time zone month, day, year, and tz
	 */
	public static String dateDisplayInUserZone(long timeMs)
	{
		// use the end-user's locale and time zone prefs
		Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		DateFormat dateFormat = new SimpleDateFormat("MMM dd, yyyy", userLocale);
		dateFormat.setTimeZone(userZone);

		// add a ms to get the next (outside of range) minute
		String rv = dateFormat.format(new Date(timeMs));
		return rv;
	}

	/**
	 * Parse a Date from a date display string in the user's time zone.
	 * 
	 * @param value
	 *        The display string.
	 * @return The Date
	 * @throws IllegalArgumentException
	 *         if the value does not parse.
	 */
	public static Date dateFromDateDisplayInUserZone(String value)
	{
		// use the end-user's locale and time zone prefs
		Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		DateFormat dateFormat = new SimpleDateFormat("MMM dd, yyyy", userLocale);
		dateFormat.setTimeZone(userZone);

		try
		{
			Date date = dateFormat.parse(value);

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
	 * Parse a Date from a date/time display string in the user's time zone.
	 * 
	 * @param value
	 *        The display string.
	 * @return The Date
	 * @throws IllegalArgumentException
	 *         if the value does not parse.
	 */
	public static Date dateFromDateTimeDisplayInUserZone(String value)
	{
		// use the end-user's locale and time zone prefs
		Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		DateFormat dateFormat = new SimpleDateFormat("MMM dd, yyyy hh:mm a", userLocale);
		dateFormat.setTimeZone(userZone);

		try
		{
			Date date = dateFormat.parse(value);

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
	 * @return date and Time formatted for the user's time zone month, day, year, and tz
	 */
	public static String dateTimeDisplayInUserZone(long timeMs)
	{
		// use the end-user's locale and time zone prefs
		Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		DateFormat dateFormat = new SimpleDateFormat("MMM dd, yyyy hh:mm a", userLocale);
		dateFormat.setTimeZone(userZone);

		// add a ms to get the next (outside of range) minute
		String rv = dateFormat.format(new Date(timeMs));
		return rv;
	}

	/**
	 * @return date and Time formatted for the user's time zone month, day, year, and tz
	 */
	public static String dateTimeDisplayInUserZone(long timeMs, String userId)
	{
		// use the end-user's locale and time zone prefs
		Locale userLocale = DateHelper.getPreferredLocale(userId);
		TimeZone userZone = DateHelper.getPreferredTimeZone(userId);

		DateFormat dateFormat = new SimpleDateFormat("MMM dd, yyyy hh:mm a", userLocale);
		dateFormat.setTimeZone(userZone);

		// add a ms to get the next (outside of range) minute
		String rv = dateFormat.format(new Date(timeMs));
		return rv;
	}

	/**
	 * Make a time range for the day in the month in the year, using the user's time zone.
	 * 
	 * @param year
	 *        The year (~2013)
	 * @param month
	 *        The month (~1..12)
	 * @param day
	 *        The day (~1..31)
	 * @return The time range, or null if the day is outside of the range of days for the month.
	 */
	public static TimeRange dayInUserZone(int year, int month, int day)
	{
		// use the end-user's locale and time zone prefs
		// Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		java.util.Calendar calendar = java.util.Calendar.getInstance();
		calendar.setTimeZone(userZone);

		// ~2013
		calendar.set(java.util.Calendar.YEAR, year);

		// ~ 0 .. 11
		calendar.set(java.util.Calendar.MONTH, month - 1);

		if (day > calendar.getActualMaximum(java.util.Calendar.DAY_OF_MONTH)) return null;

		// ~1 .. 31
		calendar.set(java.util.Calendar.DAY_OF_MONTH, day);

		// ~0 .. 23
		calendar.set(java.util.Calendar.HOUR_OF_DAY, 0);

		// ~0 .. 59
		calendar.set(java.util.Calendar.MINUTE, 0);

		// ~0 .. 59
		calendar.set(java.util.Calendar.SECOND, 0);

		// ~0 .. 999
		calendar.set(java.util.Calendar.MILLISECOND, 0);

		// the first time of the day
		Date start = calendar.getTime();

		// ~0 .. 23
		calendar.set(java.util.Calendar.HOUR_OF_DAY, 23);

		// ~0 .. 59
		calendar.set(java.util.Calendar.MINUTE, 59);

		// ~0 .. 59
		calendar.set(java.util.Calendar.SECOND, 59);

		// ~0 .. 999
		calendar.set(java.util.Calendar.MILLISECOND, 999);

		// the last time of the month
		Date end = calendar.getTime();

		TimeRange rv = TimeService.newTimeRange(start.getTime(), end.getTime() - start.getTime());
		return rv;
	}

	/**
	 * Expand the official term suffix (F12) into a description like "Fall 2012".
	 * 
	 * @param suffix
	 *        the term suffix.
	 * @return The term description.
	 */
	public static String describeTerm(String suffix)
	{
		if (suffix == null) return "Project";

		suffix = suffix.toUpperCase();
		if ("DEV".equals(suffix)) return "Development";
		if (suffix.startsWith("W")) return "Winter 20" + suffix.substring(1, 3);
		if (suffix.startsWith("SP")) return "Spring 20" + suffix.substring(2, 4);
		if (suffix.startsWith("SU")) return "Summer 20" + suffix.substring(2, 4);
		if (suffix.startsWith("F")) return "Fall 20" + suffix.substring(1, 3);

		return "Project";
	}

	/**
	 * Format a boolean for transfer.
	 * 
	 * @param b
	 *        The boolean.
	 * @return The boolean as a string.
	 */
	public static String formatBoolean(Boolean b)
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
	public static String formatDateSecondsSince1970(Date date)
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
	public static String formatDateSecondsSince1970(Time date)
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
	public static String formatFloat(float f)
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
	public static String formatInt(int i)
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
	public static String formatInt(Integer i)
	{
		if (i == null) return "0";
		return i.toString();
	}

	/**
	 * Format a long for transfer
	 * 
	 * @param l
	 *        The long value
	 * @return The long as a string.
	 */
	public static String formatLong(long l)
	{
		return Long.toString(l);
	}

	/**
	 * Make a time range for the month in the year, using the user's time zone.
	 * 
	 * @param year
	 *        The year (~2013)
	 * @param month
	 *        The month (~1..12)
	 * @return The time range.
	 */
	public static TimeRange monthInUserZone(int year, int month)
	{
		// use the end-user's locale and time zone prefs
		// Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		java.util.Calendar calendar = java.util.Calendar.getInstance();
		calendar.setTimeZone(userZone);

		// ~2013
		calendar.set(java.util.Calendar.YEAR, year);

		// ~ 0 .. 11
		calendar.set(java.util.Calendar.MONTH, month - 1);

		// ~1 .. 31
		calendar.set(java.util.Calendar.DAY_OF_MONTH, 1);

		// ~0 .. 23
		calendar.set(java.util.Calendar.HOUR_OF_DAY, 0);

		// ~0 .. 59
		calendar.set(java.util.Calendar.MINUTE, 0);

		// ~0 .. 59
		calendar.set(java.util.Calendar.SECOND, 0);

		// ~0 .. 999
		calendar.set(java.util.Calendar.MILLISECOND, 0);

		// the first time of the month
		Date start = calendar.getTime();

		// ~1 .. 31
		calendar.set(java.util.Calendar.DAY_OF_MONTH, calendar.getActualMaximum(java.util.Calendar.DAY_OF_MONTH));

		// ~0 .. 23
		calendar.set(java.util.Calendar.HOUR_OF_DAY, 23);

		// ~0 .. 59
		calendar.set(java.util.Calendar.MINUTE, 59);

		// ~0 .. 59
		calendar.set(java.util.Calendar.SECOND, 59);

		// ~0 .. 999
		calendar.set(java.util.Calendar.MILLISECOND, 999);

		// the last time of the month
		Date end = calendar.getTime();

		TimeRange rv = TimeService.newTimeRange(start.getTime(), end.getTime() - start.getTime());
		return rv;
	}

	/**
	 * @return time formatted for the user's time zone with month & date, hour, minute, am/pm
	 */
	public static String timeDisplayInUserZone(long timeStartMs)
	{
		// use the end-user's locale and time zone prefs
		Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		DateFormat dateFormat = new SimpleDateFormat("MMM dd, hh:mm a", userLocale);
		dateFormat.setTimeZone(userZone);

		String rv = dateFormat.format(new Date(timeStartMs));
		return rv;
	}

	/**
	 * @return time formatted for the user's time zone with month & date, hour, minute, am/pm
	 */
	public static String timeDisplayInUserZone(long timeStartMs, long timeEndMs)
	{
		// use the end-user's locale and time zone prefs
		Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		DateFormat dateFormat = new SimpleDateFormat("MMM dd, hh:mm a", userLocale);
		dateFormat.setTimeZone(userZone);

		// add a ms to get the next (outside of range) minute, and another because recurrent events seem to be one ms short
		String rv = dateFormat.format(new Date(timeStartMs)) + " - " + dateFormat.format(new Date(timeEndMs + 2));
		return rv;
	}

	/**
	 * @param value
	 *        The value.
	 * @return a 2 digit (leading 0 if needed) string from value.
	 */
	public static String twoDigits(int value)
	{
		return ((value < 10) ? "0" : "") + Integer.toString(value);
	}

	/**
	 * @return the user's time display
	 */
	public static String zoneDisplayInUserZone(long timeMs)
	{
		// use the end-user's locale and time zone prefs
		Locale userLocale = DateHelper.getPreferredLocale(null);
		TimeZone userZone = DateHelper.getPreferredTimeZone(null);

		DateFormat dateFormat = new SimpleDateFormat("zzz Z", userLocale);
		dateFormat.setTimeZone(userZone);

		// add a ms to get the next (outside of range) minute
		String rv = dateFormat.format(new Date(timeMs));
		return rv;
	}

	/**
	 * Check if this URL is being hosted by us on this server - with a non-relative URL. Consider the primary and also any alternate URL roots.
	 * 
	 * @param url
	 *        The url to check.
	 * @return -1 if not, or the index position in the url of the start of the relative portion (i.e. after the server URL root)
	 */
	protected static int internallyHostedUrl(String url)
	{
		ServerConfigurationService service = (ServerConfigurationService) ComponentManager.get(ServerConfigurationService.class);

		// form the access root, and check for alternate ones
		String serverUrl = service.getServerUrl();
		String[] alternateUrls = service.getStrings("alternateServerUrlRoots");

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
}
