--*********************************************************************************
-- $URL: https://source.etudes.org/svn/e3/cdp/trunk/cdp-webapp/webapp/src/webapp/WEB-INF/classes/mysql/tracker.sql $
-- $Id: tracker.sql 2725 2012-03-09 20:14:57Z ggolden $
--**********************************************************************************
--
-- Copyright (c) 2012 Etudes, Inc.
-- 
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
-- 
--      http://www.apache.org/licenses/LICENSE-2.0
-- 
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
--*********************************************************************************/

-----------------------------------------------------------------------------
-- Tracker DDL
-----------------------------------------------------------------------------

-- Note: needed only for clustered server configurations

CREATE TABLE TRACKER_USER_SERVER
(
    USER_ID       VARCHAR (99),
    SERVER_ID     VARCHAR (64),
    KEY           IDX_TRACKER_USER_SERVER_U (USER_ID)
);

CREATE TABLE TRACKER_USER_SESSION
(
    USER_ID       VARCHAR (99),
    SESSION_ID    VARCHAR (36),
    UNIQUE KEY    IDX_TRACKER_USER_SESSION_U (USER_ID)
);

CREATE TABLE TRACKER_PRESENCE_SERVER
(
    USER_ID       VARCHAR (99),
    PRESENCE_ID   VARCHAR (255),
    SERVER_ID     VARCHAR (64),
    KEY           IDX_TRACKER_PRESENCE_SERVER_U (USER_ID)
);

CREATE TABLE TRACKER_SESSION_VISIT
(
    SESSION_ID    VARCHAR (36),
    SITE_ID       VARCHAR (99),
    UNIQUE KEY    IDX_TRACKER_SESSION_VISIT (SESSION_ID, SITE_ID)
);

-- needed for all server configurations

CREATE TABLE TRACKER_USER_TRACKING
(
     USER_ID      VARCHAR (99) NOT NULL,
     FIRST_VISIT  DATETIME NOT NULL,
     LAST_VISIT   DATETIME NOT NULL,
     VISITS       INT UNSIGNED,
     UNIQUE KEY   IDX_TRACKER_USER_TRACKING (USER_ID)
)
