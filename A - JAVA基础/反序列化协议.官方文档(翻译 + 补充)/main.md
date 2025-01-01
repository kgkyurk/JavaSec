本文是在官方文档的基础上翻译 + 简单补充，可查看：[序列化流协议 by Oracle JDK](https://docs.oracle.com/javase/8/docs/platform/serialization/spec/protocol.html)

官方文档对于序列化协议的讲解非常抽象，如果你没有反序列化协议基础的话，你应该先阅读我的这篇文章：[从Demo示例中分析反序列化协议](../反序列化协议分析/main.md)。然后以本文章为参考进行对照学习。

Java反序列化协议是一种用于将对象数据序列化为流格式并在需要时重新生成对象的机制。这种协议为数据的传输、存储和重新构建提供了强大的支持。以下是关于 Object Serialization Stream Protocol（对象序列化流协议）的一个简单介绍以及核心概念的翻译和扩展说明。

## 对象序列化流协议

**主题 (Topics):**

* 概述(Overview)
* 流元素(Stream Elements)
* 流协议版本(Stream Protocol Versions)
* 流格式语法(Grammar for the Stream Format)
* 示例(Example)

## 概述 (Overview)

* 结构紧凑，便于高效阅读。
* 允许仅使用流的结构和格式的知识跳过流。不需要调用任何每类代码。
* 只需要对数据进行流式访问。

## 流元素 (Stream Elements)

在流中需要一个基本结构来表示对象。每个对象的属性都需要被表示出来，包括：它的类、字段，以及由类特定方法写入和稍后读取的数据。对象在流中的表示可以通过语法规则描述。

对于以下类型的对象，流中有特殊的表示方式：空对象 (null objects)、新对象 (new objects)、类 (classes)、数组 (arrays)、字符串 (strings)、对已存在于流中的对象的引用 (back references)，每个写入流的对象都会被分配一个句柄（handle），这个句柄用于在流中引用该对象。

句柄按照顺序分配，从`0x7E0000`开始编号。当流被重置时，句柄会重新从`0x7E0000`开始编号。

在流元素中会包含多种类型的数据，下边会介绍关于流元素中的多种数据类型表示方法。

### 普通类对象

通常类对象由ObjectStreamClass来表示。同时在类的动态代理和非动态代理情况下会有不同的内容。

#### 非动态代理类

在非动态代理类的序列化描述信息(ObjectStreamClass对象)中通常包含以下内容：

* 表示当前类的流唯一标识符（SUID）
*  (Flags)一组标志，指示类的各种属性，例如类是否定义了writeObject方法，以及类是可序列化的、可外部化的还是枚举类型
  可序列化字段的数量
* 由默认机制序列化的类字段数组。对于数组和对象字段，字段的类型以字符串形式包含，该字符串必须采用Java虚拟机规范中指定的`字段描述符`格式（例如`Ljava/lang/object;`）
* 可选的块数据记录或由annotateClass方法编写的对象
* 父类型的ObjectStreamClass（如果父类不可序列化，则为null）

#### 动态代理类

动态代理类的序列化描述信息(ObjectStreamClass对象)中由以下内容表示：

* 动态代理类实现的接口数量
* 动态代理类实现的所有接口的名称，按调用class对象上的getInterfaces方法返回的顺序列出。
* 可选的块数据记录或由annotateProxyClass方法编写的对象。
* 其父类的ObjectStreamClass(序列化描述信息), `java.lang.reflect.Proxy`

### 字符串类

String对象的表示由长度信息和以修改后的UTF-8编码的字符串内容组成。

修改后的UTF-8编码与Java虚拟机以及Java.io.DataInput和DataOutput接口中使用的编码相同；它在补充字符和空字符的表示方面不同于标准UTF-8。长度信息的形式取决于修改后的UTF-8编码中字符串的长度。如果给定String的修改后的UTF-8编码长度小于65536个字节，则长度被写为2个字节，表示一个无符号的16位整数。

从Java 2平台Standard Edition v1.3开始，如果修改后的UTF-8编码中的字符串长度为65536个字节或更多，则长度以8个字节表示，表示一个有符号的64位整数。序列化流中String前面的类型代码指示用于写入String的格式。

### 数组对象的表示

* 他们的ObjectStreamClass对象。
* 数组元素的数量。
* 数组中值的顺序。值的类型隐含在数组的类型中。例如，字节数组的值的类型为byte。

### 枚举常量的表示

* 常量基枚举类型的ObjectStreamClass对象。
* 常量的名称字符串。

### 新对象的表示

注意，这里的新对象指的是在序列化流（serialization stream）中出现的新对象，即在进行序列化操作时，**第一次写入流中的对象**。这些对象通常是序列化过程中被保存的数据对象，通常是新创建的、尚未存在于流中的对象。

* 对象的最派生类，也就是最顶层的父类（即对象的实际类型）
* 对象的每个可序列化类的数据，最顶层的父类在前面。对于每个类，流的内容中包含：
  * 可序列化字段，可参考：Section 1.5, [Defining Serializable Fields for a Class](https://docs.oracle.com/javase/8/docs/platform/serialization/spec/serial-arch.html#a6250).
  * 如果类有 `writeObject`/`readObject` 方法，可能会由 `writeObject` 方法写入可选的对象和/或原始类型的块数据记录，之后会跟随一个 `endBlockData` 代码。

所有由类写入的基本数据类型都会被缓冲，并包装在块数据记录（block-data records）中。无论这些数据是通过 `writeObject` 方法写入流，还是从 `writeObject` 方法外部直接写入流，这一规则都适用。

这些数据只能通过对应的 `readObject` 方法读取，或者直接从流中读取。

通过 `writeObject` 方法写入的对象会终止任何先前的块数据记录，并根据需要以常规对象、`null` 值或回引用的形式写入。块数据记录提供了错误恢复的能力，可以丢弃任何可选数据。当从类内部调用时，流可以丢弃任何数据或对象，直到遇到 `endBlockData` 标记为止。

## 流协议版本

有必要对JDK 1.2中的序列化流格式进行更改，该格式不向后兼容JDK 1.1的所有次要版本。为了提供需要向后兼容性的情况，添加了一种功能，以指示在编写序列化流时使用什么PROTOCOL_VERSION。ObjectOutputStream.useProtocolVersion方法将用于写入序列化流的协议版本作为参数。

流协议版本如下：

* ObjectStreamConstants.PROTOCOL_VERSION_1：表示初始流格式。
* ObjectStreamConstants.PROTOCOL_VERSION_2：表示新的外部数据格式。原始数据以块数据模式写入，并以TC_ENDBLOCKDATA终止。

块数据边界已经标准化。以块数据模式写入的原始数据被规范化为不超过1024字节块。这一更改的好处是收紧了流中序列化数据格式的规范。此更改完全向后和向前兼容。

* JDK 1.2默认编写PROTOCOL_VERSION_2。
* JDK 1.1默认编写PROTOCOL_VERSION_1。
* JDK 1.1.7及更高版本可以读取这两个版本。
* JDK 1.1.7之前的版本只能读取PROTOCOL_VERSION_1。

## 流格式语法

下表包含流格式的语法。非终端符号以斜体显示。固定宽度字体的终端符号。非终结词的定义后面跟着一个“：”。定义后面是一个或多个备选方案，每个备选方案都在单独的行上。下表描述了符号：

| **Notation** | **Meaning**                                                |
| ------------ | ---------------------------------------------------------- |
| （datatype） | 此token具有指定的数据类型，例如byte。                      |
| token[n]     | token的预定义出现次数，即数组。                            |
| x0001        | 以十六进制表示的文字值。十六进制数字的数量反映了值的大小。 |
| <*xxx*>      | 从流中读取的值，用于指示数组的长度。                       |

注意，符号（utf）用于指定使用2字节长度信息写入的字符串，而（long utf）则用于指定使用8字节长度信息编写的字符串。有关详细信息，请参阅第6.2节“流元素”。

## 语法规则

序列化流由满足流规则的任何流表示。通常来说一个完整的序列化流会包含以下元素：

```java
stream:
  magic version contents		// magic number: 0xac ed, version 0x 00 05 等

contents:
  content
  contents content

content:
  object
  blockdata

object:
  newObject
  newClass
  newArray
  newString
  newEnum
  newClassDesc
  prevObject
  nullReference
  exception
  TC_RESET

newClass:
  TC_CLASS classDesc newHandle

classDesc:
  newClassDesc
  nullReference
  (ClassDesc)prevObject      // 必须为对象的类型
                             // 类描述信息

superClassDesc:				// 父类描述信息
  classDesc

newClassDesc:
  TC_CLASSDESC className serialVersionUID newHandle classDescInfo
  TC_PROXYCLASSDESC newHandle proxyClassDescInfo
classDescInfo:
  classDescFlags fields classAnnotation superClassDesc 

className:
  (utf)

serialVersionUID:
  (long)

classDescFlags:
  (byte)                  // 在终端符号和常量中定义
						// 例如类是否继承了Serialize接口

proxyClassDescInfo:		 // 代理类描述符信息
  (int)<count> proxyInterfaceName[count] classAnnotation
      superClassDesc
proxyInterfaceName:
  (utf)
fields:
  (short)<count>  fieldDesc[count]

fieldDesc:
  primitiveDesc
  objectDesc

primitiveDesc:
  prim_typecode fieldName

objectDesc:
  obj_typecode fieldName className1

fieldName:
  (utf)

className1:
  (String)object         // 包含字段类型的字符串，采用字段描述符格式
classAnnotation:
  endBlockData
  contents endBlockData  // contents written by annotateClass

prim_typecode:			// 原始数据类型的typecode
  `B'       // byte
  `C'       // char
  `D'       // double
  `F'       // float
  `I'       // integer
  `J'       // long
  `S'       // short
  `Z'       // boolean

obj_typecode:			// 对象类型的 typecode
  `[`   // array
  `L'       // L表示对象类型。放置在对象的全类名前表示这是一个对象类型，如Ljava.lang.String

newArray:
  TC_ARRAY classDesc newHandle (int)<size> values[size]

newObject:
  TC_OBJECT classDesc newHandle classdata[]  // data for each class

classdata:
  nowrclass                 // SC_SERIALIZABLE & classDescFlag &&
                            // !(SC_WRITE_METHOD & classDescFlags)
  wrclass objectAnnotation  // SC_SERIALIZABLE & classDescFlag &&
                            // SC_WRITE_METHOD & classDescFlags
  externalContents          // SC_EXTERNALIZABLE & classDescFlag &&
                            // !(SC_BLOCKDATA  & classDescFlags
  objectAnnotation          // SC_EXTERNALIZABLE & classDescFlag&& 
                            // SC_BLOCKDATA & classDescFlags

nowrclass:
  values                    // fields in order of class descriptor

wrclass:
  nowrclass

objectAnnotation:
  endBlockData
  contents endBlockData     // contents written by writeObject or writeExternal PROTOCOL_VERSION_2.
    					  // 由 writeObject 或 writeExternal 方法写入的内容遵循 PROTOCOL_VERSION_2 协议版本。

blockdata:
  blockdatashort
  blockdatalong

blockdatashort:
  TC_BLOCKDATA (unsigned byte)<size> (byte)[size]

blockdatalong:
  TC_BLOCKDATALONG (int)<size> (byte)[size]

endBlockData   :
  TC_ENDBLOCKDATA

externalContent:          // Only parseable by readExternal primitive data
  ( bytes)                // 只有通过 readExternal 方法才能解析的原始数据。
    object

externalContents:         // externalContent written by writeExternal in PROTOCOL_VERSION_1.
  externalContent         // 在 PROTOCOL_VERSION_1 协议中，由 writeExternal 方法写入的外部内容
  externalContents externalContent

newString:
  TC_STRING newHandle (utf)
  TC_LONGSTRING newHandle (long-utf)

newEnum:
  TC_ENUM classDesc newHandle enumConstantName
enumConstantName:
  (String)object
prevObject
  TC_REFERENCE (int)handle

nullReference
  TC_NULL

exception:
  TC_EXCEPTION reset (Throwable)object         reset 

magic:
  STREAM_MAGIC

version
  STREAM_VERSION

values:          // The size and types are described by the classDesc for the current object
    			// 当前对象的大小和类型是由其 classDesc 描述的。

newHandle:       // The next number in sequence is assigned to the object being serialized or deserialized
    			// 序列化或反序列化过程中，当前对象会被分配下一个序列号。

reset:           // The set of known objects is discarded so the objects of the exception do not overlap with the previously sent objects or with objects that may be sent after the exception
    			// 在处理异常时，会清除之前已经记录的对象集合，以确保异常中的对象不会与之前发送的对象或之后可能发送的对象发生重叠。

```

## 终结符号和常量

java.io.ObjectStreamConstants中的以下符号定义了流中所需要的终端和常量值。

```java
final static short STREAM_MAGIC = (short)0xaced;
final static short STREAM_VERSION = 5;
final static byte TC_NULL = (byte)0x70;
final static byte TC_REFERENCE = (byte)0x71;
final static byte TC_CLASSDESC = (byte)0x72;
final static byte TC_OBJECT = (byte)0x73;
final static byte TC_STRING = (byte)0x74;
final static byte TC_ARRAY = (byte)0x75;
final static byte TC_CLASS = (byte)0x76;
final static byte TC_BLOCKDATA = (byte)0x77;
final static byte TC_ENDBLOCKDATA = (byte)0x78;
final static byte TC_RESET = (byte)0x79;
final static byte TC_BLOCKDATALONG = (byte)0x7A;
final static byte TC_EXCEPTION = (byte)0x7B;
final static byte TC_LONGSTRING = (byte) 0x7C;
final static byte TC_PROXYCLASSDESC = (byte) 0x7D;
final static byte TC_ENUM = (byte) 0x7E;
final static  int   baseWireHandle = 0x7E0000;
```

标志字节类DescFlags可能包括以下值

```java
final static byte SC_WRITE_METHOD = 0x01; //if SC_SERIALIZABLE
final static byte SC_BLOCK_DATA = 0x08;    //if SC_EXTERNALIZABLE
final static byte SC_SERIALIZABLE = 0x02;
final static byte SC_EXTERNALIZABLE = 0x04;
final static byte SC_ENUM = 0x10;
```

如果写入流的Serializerable类具有可能已将其他数据写入流的writeObject方法，则设置标志SC_WRITE_METHOD。在这种情况下，TC_ENDBLOCKDATA标记总是用于终止该类的数据。

如果使用stream_PROTOCOL_2将Externalizable类写入流中，则设置标志SC_BLOCKDATA。默认情况下，这是用于将Externalizable对象写入JDK 1.2中的流的协议。JDK 1.1编写STREAM_PROTOCOL_1。

如果编写流的类扩展了java.io.SERIALIZABLE，但没有扩展java.io.Internalizeable，则设置标志SC_SERIALIZABLE，读取流的类也必须扩展java.io.Seralizable，并且要使用默认序列化机制。

如果写入流的类扩展了java.io.Experiazable，则设置标记SC_EXTERNALIZABLE，读取数据的类也必须扩展EXTERNALIZABLE，并且将使用其writeExternal和readExternal方法读取数据。

如果写入流的类是枚举类型，则设置标志SC_ENUM。接收器的相应类也必须是枚举类型。枚举类型常量的数据将按照第1.12节“枚举常量的序列化”中的描述进行写入和读取。

## 示例

考虑一个原始类和链表中的两个实例的情况：

```
class List implements java.io.Serializable {
    int value;
    List next;
    public static void main(String[] args) {
        try {
            List list1 = new List();
            List list2 = new List();
            list1.value = 17;
            list1.next = list2;
            list2.value = 19;
            list2.next = null;

            ByteArrayOutputStream o = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream(o);
            out.writeObject(list1);
            out.writeObject(list2);
            out.flush();
            ...
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
```

则在这个结果中包含：

```
00: ac ed 00 05 73 72 00 04 4c 69 73 74 69 c8 8a 15 >....sr..Listi...<
10: 40 16 ae 68 02 00 02 49 00 05 76 61 6c 75 65 4c >Z......I..valueL<
20: 00 04 6e 65 78 74 74 00 06 4c 4c 69 73 74 3b 78 >..nextt..LList;x<
30: 70 00 00 00 11 73 71 00 7e 00 00 00 00 00 13 70 >p....sq.~......p<
40: 71 00 7e 00 03                                  >q.~..<
```

