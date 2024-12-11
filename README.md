# JavaSec
师傅~，您看我24年底才开始学Java安全，俺还有机会吗？｡ﾟ(ﾟ´ω`ﾟ)ﾟ｡

Java安全学习笔记，记录一下自己从0开始学习Java安全的过程。网上有不少师傅的漏洞分析其实并不是非常友好，可能师傅们默认这个知识点俺已经会啦，其实俺一点都不会（哭~，5555555555。

所以本仓库的目的是希望真的能分享一些更加零基础的Java安全学习过程，同时会去调试一些师傅们的代码，比如在FastJson的TemplatesImpl漏洞利用代码中，网上很多师傅就直接给了一个base64的_bytecodes的代码的脚本图片，啊，这，师傅，我没法调试啊~，5555555。

所以你懂的，本仓库希望给的脚本或者是其他内容更加全面一些，也会加一些如IDEA怎么调试Tomcat这种类似的分享。

该github和仓库最终会对应起来：[博客园- Java安全学习指南](https://www.cnblogs.com/erosion2020/p/18558523)

## 环境准备

在调试代码的过程中，因为漏洞触发的版本可能均不相同，所以可能会用到不同版本的JDK，我记录一下我调试过程中所有的JDK，同时这里记录一下不同版本JDK的下载地址

- JDK7u80
- JDK8u66、8u71、8u73、8u121、8u231、8u431

[Oracle官方JDK8下载](https://www.oracle.com/cn/java/technologies/javase/javase8-archive-downloads.html)
[华为JDK镜像站](https://repo.huaweicloud.com/java/jdk/)
[编程宝库JDK下载地址](http://www.codebaoku.com/jdk/jdk-oracle-jdk1-8.html)
[InJDK下载地址/镜像源导航](https://injdk.cn/)

## Java基础 & 反射

Java 的 ASM、Javassist 和反射是安全研究的重要方向之一，主要集中在字节码操作和运行时行为分析上。ASM 和 Javassist 允许研究者直接操作字节码，进行漏洞利用链（Gadget Chain）的生成、恶意代码注入，以及对反序列化、动态代理等机制的深入分析；反射则是许多漏洞的核心，例如通过访问控制绕过、内存马注入或动态方法调用实现攻击。它们共同为研究 Java 平台的动态特性和潜在安全风险提供了技术支撑，是理解漏洞机制、开发利用工具和分析攻击链的基础。

- 反射机制: [JAVA反射基础知识 + 修改被private final修饰的字段](https://www.cnblogs.com/erosion2020/p/18559481)
- ClassLoader: [BootstrapClassLoader + ExtClassLoader + AppClassLoader + 双亲委派](https://www.cnblogs.com/erosion2020/p/18560806)
- 静态代理&动态代理: [静态代理 + Proxy动态代理](https://www.cnblogs.com/erosion2020/p/18561350)
- ASM: [访问者模式 + 动态操作(访问/修改)class字节码](https://www.cnblogs.com/erosion2020/p/18561454)
- RMI(远程方法调用): [RMI基本原理 + 客户端/服务端/注册中心 攻击手法 + Bypass JEP290](https://www.cnblogs.com/erosion2020/p/18568890)
- JNDI(命名空间及目录服务): [JNDI基本概念 + JNDI/RMI攻击手法 + JNDI/LDAP攻击手法](https://www.cnblogs.com/erosion2020/p/18561646)
- SPI机制: [SPI基本概念 + SPI攻击](https://www.cnblogs.com/erosion2020/p/18571153)

## 反序列化

JAVA反序列化安全学习笔记，下边的调试代码都是基于ysoserial中的代码来记录的。嗯~网上有很多魔改代码，但是如果想要标准系统化的学习的话还是要基于ysoserial这个反序列化漏洞的起源项目来学习。

- Java类转字节码工具: [Java类转Base64编码字符串 + Base64编码字符串转.class文件](https://www.cnblogs.com/erosion2020/p/18595215)

- 基础知识：[反序列化漏洞的起源 + JAVA反序列化 + URLDNS](https://www.cnblogs.com/erosion2020/p/18553335)

- ### CC链

  `CommonsCollections(CC)`反序列化攻击链

  - CC1攻击链：[AnnotationInvocationHandler + Proxy + LazyMap + Transformer](https://www.cnblogs.com/erosion2020/p/18553568)
  - CC2攻击链：[PriorityQueue + TransformingComparator + Transformer + TemplatesImpl](https://www.cnblogs.com/erosion2020/p/18553815)
  - CC3攻击链：[AnnotationInvocationHandler + Proxy + LazyMap + Transformer + TrAXFilter + TemplatesImpl](https://www.cnblogs.com/erosion2020/p/18554451)
  - CC4攻击链：[PriorityQueue + TransformingComparator + TrAXFilter + TemplatesImpl](https://www.cnblogs.com/erosion2020/p/18554783)
  - CC5攻击链：[BadAttributeValueExpException + TiedMapEntry + LazyMap + Transformer](https://www.cnblogs.com/erosion2020/p/18555069)
  - CC6攻击链：[HashSet + HashMap + TiedMapEntry + LazyMap + Transformer](https://www.cnblogs.com/erosion2020/p/18555609)
  - CC7攻击链：[HashTable + TiedMapEntry + LazyMap + Transformer](https://www.cnblogs.com/erosion2020/p/18555705)

  ### CB链

  `CommonsBeanUtils(CB)`反序列化攻击链

  - CB1攻击链：[PriorityQueue + BeanComparator + TemplatesImpl](https://www.cnblogs.com/erosion2020/p/18556800)

## 内存马

内存马是一种无文件Webshell，简单来说就是服务器上不会存在需要链接的webshell脚本文件。 传统webshell会在目标服务器中留存具体的payload文件，但现在安全软件对于静态webshell的查杀能力已经非常的强，可能payload文件在写入的一瞬间就会被查杀，而内存马的原理就是在web组件或者应用程序中，注册一层访问路由，访问者通过这层路由，来执行我们控制器中的代码，一句话就能概括，那就是对访问路径映射及相关处理代码的动态注册。

- JAVA WEB & Tomcat: [Servlet + Filter + Listener + Connector(连接器) + Container(Servlet容器)](https://www.cnblogs.com/erosion2020/p/18573756)
- JAVA WEB环境搭建: [Tomcat安装 + IDEA创建JAVA WEB项目 + IDEA开启调试Tomcat](https://www.cnblogs.com/erosion2020/p/18574152)
- Servlet内存马: [Context概念 + Debug Servlet加载过程 + 补充内容](https://www.cnblogs.com/erosion2020/p/18575039)
- Listener内存马: [Listener示例 + ApplicationListener Debug + Listener内存马代码](https://www.cnblogs.com/erosion2020/p/18575391)
- Filter内存马: [Filter代码Debug + Filter内存马代码 + 运行](https://www.cnblogs.com/erosion2020/p/18577056)

## 漏洞复现篇

准备把自己分析漏洞的过程都记录下来，然后分类(就按攻击手法来分类了，不按组件来分类了，感觉按照攻击手法来分类更容易学习)，到时候回来想看的话也非常好找

JNDI注入

- log4j2 注入/远程代码执行 漏洞 CVE-2021-44228: [log4j2漏洞点分析 + 代码分析 + JNDIExploit攻击工具分析](https://www.cnblogs.com/erosion2020/p/18583981)
- log4j2 注入/远程代码执行-2 漏洞 [WAF绕过 + 协议总结 + 信息泄露用法](https://www.cnblogs.com/erosion2020/p/18584933)
