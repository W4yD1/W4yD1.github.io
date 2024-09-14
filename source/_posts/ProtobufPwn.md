---
title: ProtobufPwn
date: 2024-05-29 18:16:41
tags: [笔记, ProtobufPwn]
categories: 
    - 笔记
---

# 还原.proto文件

## pbtk

```shell
./extractors/from_binary.py [-h] input_file [output_dir]
```

## 逆向
先找到字段字符串
![](1.png)

然后通过交叉引用找到message字段的结构体，一般在`.data.rel.ro`段
![](2.png)

结构体各字段具体如下：
```C
struct ProtobufCFieldDescriptor {
	/** Name of the field as given in the .proto file. */
	const char		*name;
	/** Tag value of the field as given in the .proto file. */
	uint32_t		id;
	/** Whether the field is `REQUIRED`, `OPTIONAL`, or `REPEATED`. */
	ProtobufCLabel		label;
	/** The type of the field. */
	ProtobufCType		type;
	/**
	 * The offset in bytes of the message's C structure's quantifier field
	 * (the `has_MEMBER` field for optional members or the `n_MEMBER` field
	 * for repeated members or the case enum for oneofs).
	 */
	unsigned		quantifier_offset;
	/**
	 * The offset in bytes into the message's C structure for the member
	 * itself.
	 */
	unsigned		offset;
	/**
	 * A type-specific descriptor.
	 *
	 * If `type` is `PROTOBUF_C_TYPE_ENUM`, then `descriptor` points to the
	 * corresponding `ProtobufCEnumDescriptor`.
	 *
	 * If `type` is `PROTOBUF_C_TYPE_MESSAGE`, then `descriptor` points to
	 * the corresponding `ProtobufCMessageDescriptor`.
	 *
	 * Otherwise this field is NULL.
	 */
	const void		*descriptor; /* for MESSAGE and ENUM types */
	/** The default value for this field, if defined. May be NULL. */
	const void		*default_value;
	/**
	 * A flag word. Zero or more of the bits defined in the
	 * `ProtobufCFieldFlag` enum may be set.
	 */
	uint32_t		flags;
	/** Reserved for future use. */
	unsigned		reserved_flags;
	/** Reserved for future use. */
	void			*reserved2;
	/** Reserved for future use. */
	void			*reserved3;
};
```

label对应枚举如下：
```C
typedef enum {
	/** A well-formed message must have exactly one of this field. */
	PROTOBUF_C_LABEL_REQUIRED,
	/**
	 * A well-formed message can have zero or one of this field (but not
	 * more than one).
	 */
	PROTOBUF_C_LABEL_OPTIONAL,
	/**
	 * This field can be repeated any number of times (including zero) in a
	 * well-formed message. The order of the repeated values will be
	 * preserved.
	 */
	PROTOBUF_C_LABEL_REPEATED,
	/**
	 * This field has no label. This is valid only in proto3 and is
	 * equivalent to OPTIONAL but no "has" quantifier will be consulted.
	 */
	PROTOBUF_C_LABEL_NONE,
} ProtobufCLabel;
```
type对应枚举如下：
| Protobuf C Type              | C Type                  | Line Number Minus One (Hex) |
|------------------------------|-------------------------|-----------------------------|
| PROTOBUF_C_TYPE_INT32        | int32                   | 0x0                         |
| PROTOBUF_C_TYPE_SINT32       | signed int32            | 0x1                         |
| PROTOBUF_C_TYPE_SFIXED32     | signed int32 (4 bytes)  | 0x2                         |
| PROTOBUF_C_TYPE_INT64        | int64                   | 0x3                         |
| PROTOBUF_C_TYPE_SINT64       | signed int64            | 0x4                         |
| PROTOBUF_C_TYPE_SFIXED64     | signed int64 (8 bytes)  | 0x5                         |
| PROTOBUF_C_TYPE_UINT32       | unsigned int32          | 0x6                         |
| PROTOBUF_C_TYPE_FIXED32      | unsigned int32 (4 bytes)| 0x7                         |
| PROTOBUF_C_TYPE_UINT64       | unsigned int64          | 0x8                         |
| PROTOBUF_C_TYPE_FIXED64      | unsigned int64 (8 bytes)| 0x9                         |
| PROTOBUF_C_TYPE_FLOAT        | float                   | 0xA                         |
| PROTOBUF_C_TYPE_DOUBLE       | double                  | 0xB                         |
| PROTOBUF_C_TYPE_BOOL         | boolean                 | 0xC                         |
| PROTOBUF_C_TYPE_ENUM         | enumerated type         | 0xD                         |
| PROTOBUF_C_TYPE_STRING       | UTF-8 or ASCII string   | 0xE                         |
| PROTOBUF_C_TYPE_BYTES        | arbitrary byte sequence | 0xF                         |
| PROTOBUF_C_TYPE_MESSAGE      | nested message          | 0x10                        |

下图
![](2.png)
对应的message为：
```proto
bytes whatcon = 1;
```

# 编译proto文件

```shell
protoc proto_file.proto --python_out ./
```

编译完成后生成一个proto_file_pb2.py文件，在脚本中通过`import proto_file_pb2`引用，通过`cont = proto_file_pb2.devicemsg()`创建message对象，其中devicemsg为.proto文件内的message结构体名称，通过cont.whatcon=b'aaaa'赋值，最后通过cont.SerializeToString()解析然后发送。


