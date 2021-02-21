---
title: Set http redirection for covenant
description: External c2 is not much to say, it is a technology to prevent the real c2 address from leaking and wasting resources and time after being banned by the Blue Team.
categories:
 - RedTeam Skill
tags:
 - http
 - covenant
---

## *No.1 Preface*

External c2 is not much to say, it is a technology to prevent the real c2 address from leaking and wasting resources and time after being banned by the Blue Team.

Well, the following describes how to set up http redirection for covenant c2.

## *No.2 Text*

First configure apache on external vps.

Then, install apache.

`apt-get install apache2`

And open the forwarding module of apache.

`a2enmod rewrite proxy proxy_http proxy_connect`

After that, we can establish site configuration.

`a2ensite 000-default.conf`

Well, restart apache.

`service apache2 restart`

After apache is configured, set up a listen on covenant: (ConnectAddresses is set to the ip of apache, and the port should be the same as the port opened by apache.)

![image.png]({{site.url}}/upload/2021-02-21-Set-http-redirection-for-covenant/w9JdKnvlLX8My2I.png)

You can look at the profile after moving. (Because this is a demonstration, the Profile is the default and could be changed later according to your own needs.)

![image.png]({{site.url}}/upload/2021-02-21-Set-http-redirection-for-covenant/LTk7J3MtyAcsZbC.png)

According to the profile, write forward on apache:

First, we need to edit the site profile,

`vim /etc/apache2/sites-enabled/000-default.conf`

And then, we could add under `CustomLog ${APACHE_LOG_DIR}/accessi.log combined`

```ini
ProxyRequests off
ProxyPass /en-us/index.html http://xx.xx.xx.xx/en-us/index.html
ProxyPassReverse /en-us/index.html http://xx.xx.xx.xx /en-us/index.html
ProxyPass /en-us/docs.html http://xx.xx.xx.xx /en-us/docs.html
ProxyPassReverse /en-us/docs.html http://xx.xx.xx.xx /en-us/docs.html
ProxyPass /en-us/test.html http://xx.xx.xx.xx /en-us/test.html
ProxyPassReverse /en-us/test.html http://xx.xx.xx.xx /en-us/test.html
```

(xx.xx.xx.xx writes the ip of covenant c2 to forward the request to c2)

Restart apache after saving

`service apache2 restart`

Then edit the access conditions and jump successfully

![image.png]({{site.url}}/upload/2021-02-21-Set-http-redirection-for-covenant/GQw85ZeKautmpLU.png)

Look at the effect:

Generate a binary loader.

![image.png]({{site.url}}/upload/2021-02-21-Set-http-redirection-for-covenant/94UpvWuNP8Jtsna.png)

And run successfully.

![image.png]({{site.url}}/upload/2021-02-21-Set-http-redirection-for-covenant/Ui7e63ajbrxquJ2.png)

Network traffic can only see traffic to external vps.

![image.png]({{site.url}}/upload/2021-02-21-Set-http-redirection-for-covenant/PHIb74cOrZi3yve.png)

## *NO.3 Copyright Notice*

Any direct or indirect consequences and losses caused by the dissemination and utilization of the information provided in this article shall be borne by the user himself, and Bounty Team and the author of this article shall not bear any responsibility for this. Bounty Team has the right to modify and interpret this article. If you want to reprint or disseminate this article, you must ensure the integrity of this article, including all contents such as copyright notice. Without permission from Bounty Team, the content of this article shall not be arbitrarily modified, increased or decreased, and it shall not be used for commercial purposes in any way.

## *NO.4 Author*

>  thr0cyte@Bounty Team - DBAPPSecurity
