package pfkey

// PF_KEY related data structures. Taken from rfc2367

// SADBMsg represents the base sadb_msg struct from rfc2367
type SADBMsg struct {
	Version  uint8
	Type     uint8
	Errno    uint8
	SAType   uint8
	Len      uint16
	Reserved uint16
	Seq      uint32
	PID      uint32
}

// SADBExt holds the basic information for an extension (len and type)
type SADBExt struct {
	Len  uint16
	Type uint16
}

// SADBSA holds the sadb_sa extension for a PF_KEY message.
type SADBSA struct {
	Len     uint16
	ExtType uint16
	SPI     uint32
	Replay  uint8
	State   uint8
	Auth    uint8
	Encrypt uint8
	Flags   uint32
}

// SADBLifetime holds a sadb_lifetime extension for a PF_KEY message.
type SADBLifetime struct {
	Len         uint16
	ExtType     uint16
	Allocations uint32
	Bytes       uint64
	Addtime     uint64
	Usetime     uint64
}

// SADBAddress holds a sadb_address extension for a PF_KEY message.
type SADBAddress struct {
	Len       uint16
	ExtType   uint16
	Proto     uint8
	PrefixLen uint8
	Reserved  uint16
}

// SADBKey holds a sadb_key extension for a PF_KEY message.
type SADBKey struct {
	Len      uint16
	ExtType  uint16
	Bits     uint16
	Reserved uint16
}

// SADBProp holds sadb_prop extension for a PF_KEY message.
type SADBProp struct {
	Len      uint16
	ExtType  uint16
	Replay   uint8
	Reserved [3]uint8
}

// SADBComb holds a sadb_comb extension for a PF_KEY message.
type SADBComb struct {
	Auth            uint8
	Encrypt         uint8
	Flags           uint16
	AuthMinBits     uint16
	AuthMaxBits     uint16
	Reserved        uint32
	SoftAllocations uint32
	HardAllocations uint32
	SoftBytes       uint64
	HardBytes       uint64
	SoftAddTime     uint64
	HardAddtime     uint64
	SoftUsetime     uint64
	HardUseTime     uint64
}

// SADBXPolicy holds a sadb_X_Policy extension for a PF_KEY message.
type SADBXPolicy struct {
	Len      uint16
	ExtType  uint16
	Type     uint16
	Dir      uint8
	Reserved uint8
	ID       uint32
	Priority uint32
}

// SADBSupported holds a sadb_supported extension for a PF_KEY message.
type SADBSupported struct {
	Len      uint16
	ExtType  uint16
	Reserved uint32
}

// SADBAlg holds a sadb_alg extension for a PF_KEY message.
type SADBAlg struct {
	ID       uint8
	IVLen    uint8
	MinBits  uint16
	MaxBits  uint16
	Reserved uint16
}

// SADBSPIRange holds a sadb_spirange extension for a PF_KEY message.
type SADBSPIRange struct {
	Len      uint16
	ExtType  uint16
	Min      uint32
	Max      uint32
	Reserved uint32
}
