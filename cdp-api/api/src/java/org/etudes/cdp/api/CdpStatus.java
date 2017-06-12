/**********************************************************************************
 * $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-api/api/src/java/org/etudes/cdp/api/CdpStatus.java $
 * $Id: CdpStatus.java 5102 2013-06-05 21:36:09Z ggolden $
 ***********************************************************************************
 *
 * Copyright (c) 2011, 2012, 2013 Etudes, Inc.
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

/**
 * CdpStatus ...
 */
public enum CdpStatus
{
	accessDenied(1), badRequest(5), notLoggedIn(2), serverUnavailable(3), oldVersion(4), success(0);

	static public final String CDP_STATUS = "cdp:status";

	private final Integer id;

	private CdpStatus(int id)
	{
		this.id = Integer.valueOf(id);
	}

	public Integer getId()
	{
		return this.id;
	}
}
