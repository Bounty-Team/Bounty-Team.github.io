---
title: Analysis of Weblogic T3/IIOP Deserialization Vulnerability (XXE Vulnerability)
description: Weblogic T3/IIOP Deserialization & XXE Analysis
categories:
 - Vulnerability Analysis
tags:
 - weblogic
 - XXE
 - Vulnerability Analysis
 - RCE
---


## ***Screenshot of Vulnerability Repetition Proof***

![image.png]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/1.png)

## ***Scope of influence***

Oracle Weblogic Server 12.1.3.0, 12.2.1.3, 12.2.1.4

## ***Vulnerability Analysis***

`com.tangosol.util.ExternalizableHelper#readXmlSerializable` will pass the `sXml` read by deserialization into `(new SimpleParser()).parseXml` for XML parsing.

![image.png]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/2.png)

Following `parseXml`, `this.parseDocument (xml)` parses the xml string we passed in into an `XmlDocument` object.

![image.png]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/3.png)

If `this.m_fValidate` is true, call `(new SaxParser ()). ValidateXsd (sXml, xml)` validates the xml format, which is true by default.

![image.png]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/4.png)

Following the `validateXsd` method, the XXE vulnerability will eventually be triggered by a call to `validator.validate (source)`, which is the `source` object of the xml we passed in. But only if `listSchemaURIs` are not empty.

![image.png]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/5.png)

Take a look at the assignment process for `listSchemaURIs`

`XmlHelper.getNamespacePrefix` gets the label attribute that starts with `xmlns`: and returns the string following it as the `prefix`.

![image.png]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/6.png)

`XmlHelper.getSchemaLocations` extracts the value of `prefix +: schemaLocation` or: `noNamespaceSchemaLocation`, splits it by whitespace and adds it to `listURLs` every two bits.

![image.png]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/7.png)

Therefore, we construct the following format to make `listSchemaURIs` not empty.

```xml
<a xmlns:x='http://www.w3.org/2001/XMLSchema-instance'
   x:schemaLocation='http://www.springframework.org/schema/mvc
   http://www.springframework.org/schema/mvc/spring-mvc.xsd'/>
```

Follow `this.resolveSchemaSources (listSchemaURIs)`,

![image-20210128164329642]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/8.png)

`AppCLassLoader` will eventually be called to find the resource file in the URI locally instead of loading it remotely.

![image-20210128164519438]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/9.png)

So we need to find a workable XSD file locally, and I’m using `coherence-rest-config. Xsd` from `Coherence.jar`, so replaces `http://www.springframework.org/schema/mvc/spring-mvc.xsd` with `http://www.springframework.org/coherence-rest-config.xsd.`

![image-20210128164822077]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/10.png)

Finally, we still need to go to the deserialization entry in `com.tangosol.util.ExternalizableHelper # readXmlSerializable`, which can also be used with CVE-2020-14756. The corresponding nType of `com.tangosol.coherence.servlet.AttributeHolder readXmlSerializable` is 9.

![img]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/11.png)

We can override `AttributeHolder’s writeExternal` method and write the custom XML directly according to the reading process during deserialization.

![img]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/12.png)

## ***Vulnerability Repair***

The false parameter passed in when instantiating `SimpleParser` prevents validation of XML format.

![img]({{site.url}}/upload/2021-01-29-Analysis-of-Weblogic-T3IIOP-XXE/13.png)

## ***Author***

> Smi1e@WEBIN.LAB - DBAPPSecurity
