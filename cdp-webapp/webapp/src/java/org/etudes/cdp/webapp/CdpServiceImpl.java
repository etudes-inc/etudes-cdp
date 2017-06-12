/**********************************************************************************
 * $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-webapp/webapp/src/java/org/etudes/cdp/webapp/CdpServiceImpl.java $
 * $Id: CdpServiceImpl.java 5102 2013-06-05 21:36:09Z ggolden $
 ***********************************************************************************
 *
 * Copyright (c) 2013 Etudes, Inc.
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

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.etudes.cdp.api.CdpHandler;
import org.etudes.cdp.api.CdpService;

/**
 * Tracker ...<br />
 */
public class CdpServiceImpl implements CdpService
{
	/** Our log. */
	private static Log M_log = LogFactory.getLog(CdpServiceImpl.class);

	/** Map of request prefix -> cdp handler. */
	protected Map<String, CdpHandler> handlers = new HashMap<String, CdpHandler>();

	/**
	 * Construct
	 */
	public CdpServiceImpl()
	{
		M_log.info("CdpServiceImpl: construct");
	}

	/**
	 * Stop the maintenance thread, deal with any remaining users.
	 */
	public void destroy()
	{
		M_log.info("CdpServiceImpl: destroy");
	}

	public CdpHandler getCdpHandler(String prefix)
	{
		return this.handlers.get(prefix);
	}

	public void registerCdpHandler(CdpHandler handler)
	{
		this.handlers.put(handler.getPrefix(), handler);
	}

	public void UnregisterCdpHandler(CdpHandler handler)
	{
		this.handlers.remove(handler);
	}
}
