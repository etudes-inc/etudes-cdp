/**********************************************************************************
 * $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-api/api/src/java/org/etudes/cdp/api/CdpHandler.java $
 * $Id: CdpHandler.java 5102 2013-06-05 21:36:09Z ggolden $
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

package org.etudes.cdp.api;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * CdpHandler ...
 */
public interface CdpHandler
{
	/**
	 * @return The handler's request prefix.
	 */
	String getPrefix();

	/**
	 * Handle a request.
	 */
	Map<String, Object> handle(HttpServletRequest req, HttpServletResponse res, Map<String, Object> parameters, String requestPath, String path, String authenticatedUserId)
			throws ServletException, IOException;
}
