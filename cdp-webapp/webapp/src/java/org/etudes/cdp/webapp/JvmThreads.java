/**********************************************************************************
 * $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-webapp/webapp/src/java/org/etudes/cdp/webapp/JvmThreads.java $
 * $Id: JvmThreads.java 7694 2014-03-25 21:13:45Z ggolden $
 ***********************************************************************************
 *
 * Copyright (c) 2014 Etudes, Inc.
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

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Log active JVM threads handling requests.
 */
public class JvmThreads
{
	protected static class Reporter implements Runnable
	{
		/** if true, report each time. */
		protected boolean details = false;

		protected long sleepTime = 0l;

		/** The maintenance thread. */
		protected Thread thread = null;

		/** The thread quit flag. */
		protected boolean threadStop = false;

		public Reporter(long sleepTime, boolean details)
		{
			this.details = details;
			this.sleepTime = sleepTime;
		}

		public void run()
		{
			// loop till told to stop
			int maxActive = 0;
			while ((!threadStop) && (!Thread.currentThread().isInterrupted()))
			{
				maxActive = dumpThreads(maxActive, details);

				try
				{
					Thread.sleep(sleepTime);
				}
				catch (Exception ignore)
				{
				}
			}

			M_log.info("Max Active Requests: " + maxActive);
		}

		/**
		 * Start the clean and report thread.
		 */
		protected void start()
		{
			threadStop = false;

			thread = new Thread(this, getClass().getName());
			thread.start();
		}

		/**
		 * Stop the clean and report thread.
		 */
		protected void stop()
		{
			if (thread == null) return;

			// signal the thread to stop
			threadStop = true;

			// wake up the thread
			thread.interrupt();
			thread = null;
		}
	}

	protected static Reporter reporter = null;

	/** Our log. */
	private static Log M_log = LogFactory.getLog(JvmThreads.class);

	/**
	 * Dump a report of all threads.
	 */
	public static int dumpThreads(int maxSoFar, boolean details)
	{
		int rv = maxSoFar;
		int activeCount = 0;
		StringBuilder buf = new StringBuilder();
		Map<Thread, StackTraceElement[]> traces = Thread.getAllStackTraces();
		for (Map.Entry<Thread, StackTraceElement[]> e : traces.entrySet())
		{
			if ((!e.getKey().getName().startsWith("TP-Processor")) && (!e.getKey().getName().startsWith("http-8080"))) continue;
			boolean active = false;
			for (StackTraceElement el : e.getValue())
			{
				if (el.getClassName().equals("javax.servlet.http.HttpServlet") && (el.getMethodName().equals("service"))) active = true;
			}

			if (active)
			{
				if (details)
				{
					if (activeCount > 0) buf.append(", ");
					buf.append(e.getKey().getName());
				}
				activeCount++;
			}
		}

		if (activeCount > 0)
		{
			if (maxSoFar < activeCount)
			{
				rv = activeCount;
			}

			if (details)
			{
				buf.insert(0, activeCount + " (" + rv + ") : ");
				M_log.info(buf.toString());
			}
		}

		return rv;
	}

	public static void startReporting(long sleepTime, boolean details)
	{
		if (reporter == null)
		{
			reporter = new Reporter(sleepTime, details);
			reporter.start();
		}
	}

	public static void stopReporting()
	{
		if (reporter != null)
		{
			reporter.stop();
			reporter = null;
		}
	}
}
