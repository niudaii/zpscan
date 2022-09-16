//nolint
package wmiexec

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/C-Sto/goWMIExec/pkg/uuid"
)

type DCOMORPCThis struct {
	VersionMajor uint16
	VersionMinor uint16
	Flags        uint32
	Reserved     uint32
	CausalityID  [16]byte
	Unknown      uint32
}

type IActProperties struct {
	CntData uint32
	OBJREF  OBJREF
}

type OBJREF struct {
	Signature    uint32
	Flags        uint32
	IID          [16]byte
	CUSTOMOBJREF CUSTOMOBJREF
}

type CUSTOMOBJREF struct {
	CLSID          [16]byte
	CBExtension    uint32
	Size           uint32
	IActProperties IActProperties2
}

//idk man, I'm doing this from the wireshark dissection, not the standard ok
type IActProperties2 struct {
	TotalSize    uint32
	Reserved     uint32
	CustomHeader CustomHeader
	Properties   IAct2Properties
}

type CustomHeader struct {
	CommonHeader                  CommonTypeHeader
	PrivateHeader                 PrivateHeader
	TotalSize                     uint32
	CustomHeaderSize              uint32
	Reserved                      uint32
	DestinationContext            uint32
	NumActivationProptertyStructs uint32
	ClassInfoClsid                [16]byte
	ClsId                         ClsId
}

type CommonTypeHeader struct {
	Version            byte
	Endianness         byte
	CommonHeaderLength uint16
	Filler             uint32
}

func NewCommonHeader1(endian int) CommonTypeHeader {
	return CommonTypeHeader{
		Version:            1,
		Endianness:         0x10, //little endian
		CommonHeaderLength: 8,
		Filler:             0xcccccccc,
	}
}

type PrivateHeader struct {
	ObjectBufferLength uint32
	Filler             uint32
}

func NewPrivateHeader(buflen uint32) PrivateHeader {
	return PrivateHeader{
		ObjectBufferLength: buflen,
		Filler:             0x0000,
	}
}

type ClsId struct {
	PtrReferentID             uint32
	PtrSizesReferentID        uint32
	NULLPointer               uint32
	PtrMaxCount               uint32
	PtrPropertyStructGUID     [16]byte
	PtrPropertyStructGUID2    [16]byte
	PtrPropertyStructGUID3    [16]byte
	PtrPropertyStructGUID4    [16]byte
	PtrPropertyStructGUID5    [16]byte
	PtrPropertyStructGUID6    [16]byte
	SizesPtrMaxCount          uint32
	SizesPtrPropertyDataSize  uint32
	SizesPtrPropertyDataSize2 uint32
	SizesPtrPropertyDataSize3 uint32
	SizesPtrPropertyDataSize4 uint32
	SizesPtrPropertyDataSize5 uint32
	SizesPtrPropertyDataSize6 uint32
}

type IAct2Properties struct {
	SpecialSystemProperties SpecialSystemProperties
	InstantiationInfo       InstantiationInfo
	ActivationContextInfo   ActivationContextInfo
	SecurityInfo            SecurityInfo
	LocationInfo            LocationInfo
	ScmRequestInfo          ScmRequestInfo
}

type SpecialSystemProperties struct {
	CommonHeader         CommonTypeHeader
	PrivateHeader        PrivateHeader
	SessionID            uint32
	RemoteThisSessionID  uint32
	ClientImpersonating  uint32
	PartitionIDPresent   uint32
	DefaultAuthnLevel    uint32
	PartitionGUID        [16]byte
	ProcessRequestFlags  uint32
	OriginalClassContext uint32
	Flags                uint32
	Reserved             [32]byte
	UnusedBuffer         uint64
}

type InstantiationInfo struct {
	CommonHeader            CommonTypeHeader
	PrivateHeader           PrivateHeader
	InstantiatedObjectClsId [16]byte
	ClassContext,
	ActivationFlags,
	FlagsSurrogate,
	InterfaceIdCount,
	InstantiationFlag,
	InterfaceIdsPtr,
	EntirePropertySize uint32
	VersionMajor, VersionMinor uint16
	InterfaceIdsMaxCount       uint32
	InterfaceIds               [16]byte
	UnusedBuffer               uint32
}

type ActivationContextInfo struct {
	CommonHeader                                        CommonTypeHeader
	PrivateHeader                                       PrivateHeader
	ClientOk                                            uint32
	Reserved                                            uint32
	Reserved2                                           uint32
	Reserved3                                           uint32
	ClientPtrReferentID                                 uint32
	NULLPtr                                             uint32
	ClientPtrClientContextUnknown                       uint32
	ClientPtrClientContextCntData                       uint32
	ClientPtrClientContextOBJREFSignature               uint32
	ClientPtrClientContextOBJREFFlags                   uint32
	ClientPtrClientContextOBJREFIID                     [16]byte
	ClientPtrClientContextOBJREFCUSTOMOBJREFCLSID       [16]byte
	ClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension uint32
	ClientPtrClientContextOBJREFCUSTOMOBJREFSize        uint32
	UnusedBuffer                                        [48]byte
}

type SecurityInfo struct {
	CommonHeader                        CommonTypeHeader
	PrivateHeader                       PrivateHeader //", packet_private_header);
	AuthenticationFlags                 uint32
	ServerInfoPtrReferentID             uint32
	NULLPtr                             uint32
	ServerInfoServerInfoReserved        uint32
	ServerInfoServerInfoNameReferentID  uint32
	ServerInfoServerInfoNULLPtr         uint32
	ServerInfoServerInfoReserved2       uint32
	ServerInfoServerInfoNameMaxCount    uint32 //", packet_target_length);
	ServerInfoServerInfoNameOffset      uint32
	ServerInfoServerInfoNameActualCount uint32 //", packet_target_length);
	ServerInfoServerInfoNameString      []byte // uint32//uint", packet_target_unicode);

}

type LocationInfo struct {
	CommonHeader  CommonTypeHeader
	PrivateHeader PrivateHeader
	NULLPtr       uint32
	ProcessID     uint32
	ApartmentID   uint32
	ContextID     uint32
}

type ScmRequestInfo struct {
	CommonHeader                                                 CommonTypeHeader
	PrivateHeader                                                PrivateHeader
	NULLPtr                                                      uint32
	RemoteRequestPtrReferentID                                   uint32
	RemoteRequestPtrRemoteRequestClientImpersonationLevel        uint32
	RemoteRequestPtrRemoteRequestNumProtocolSequences            uint16
	RemoteRequestPtrRemoteRequestUnknown                         uint16
	RemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID  uint32
	RemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount    uint32
	RemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq uint16
	UnusedBuffer                                                 [6]byte // = 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
}

type PacketDCOMRemoteInstance struct {
	/*
		DCOMVersionMajor                                                                                                             uint16
		DCOMVersionMinor                                                                                                             uint16
		DCOMFlags                                                                                                                    uint32
		DCOMReserved                                                                                                                 uint32
		DCOMCausalityID                                                                                                              [16]byte
		Unknown                                                                                                                      uint32
	*/
	DCOMORPCThis   DCOMORPCThis
	Unknown2       uint32
	Unknown3       uint32
	Unknown4       uint32
	IActProperties IActProperties
}

func NewDCOMRemoteInstance(causality [16]byte, target string) PacketDCOMRemoteInstance {
	r := PacketDCOMRemoteInstance{}

	targetU, _ := toUnicodeS(target)
	targetL := uint32(len(target)) + 1

	targetB := []byte(targetU)

	b := uint32(math.Trunc(float64(len(targetB))/8+1)*8 - float64(len(targetB)))
	nulls := make([]byte, b)
	targetB = append(targetB, nulls...)

	targetCnt := uint32(len(targetB)) + 720
	pktSize := uint32(len(targetB)) + 680
	pktTotal := uint32(len(targetB)) + 664
	privHeader := uint32(len(targetB) + 40)
	propDataSize := uint32(len(targetB) + 56)

	r.DCOMORPCThis.VersionMajor = 0x05
	r.DCOMORPCThis.VersionMinor = 0x07
	r.DCOMORPCThis.Flags = 0x01
	r.DCOMORPCThis.Reserved = 0x00
	r.DCOMORPCThis.CausalityID = causality // packet_causality_ID);
	r.DCOMORPCThis.Unknown = 0x00
	r.Unknown2 = 0x00
	r.Unknown3 = 0x020000
	r.Unknown4 = targetCnt //", packet_cntdata);

	r.IActProperties.CntData = targetCnt           //", packet_cntdata);
	r.IActProperties.OBJREF.Signature = 0x574f454d // 0x4d, 0x45, 0x4f, 0x57
	r.IActProperties.OBJREF.Flags = 0x04
	r.IActProperties.OBJREF.IID = uuid.IID_IActivationPropertiesIn
	r.IActProperties.OBJREF.CUSTOMOBJREF.CLSID = uuid.CLSID_ActivationPropertiesIn
	r.IActProperties.OBJREF.CUSTOMOBJREF.CBExtension = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.Size = pktSize                      //", packet_size);
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.TotalSize = pktTotal //", packet_total_size);
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Reserved = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.CommonHeader = NewCommonHeader1(0x10)  //
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.PrivateHeader = NewPrivateHeader(0xb0) // 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.TotalSize = pktTotal                   //", packet_total_size);
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.CustomHeaderSize = 0xc0
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.Reserved = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.DestinationContext = 0x02
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.NumActivationProptertyStructs = 0x06
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClassInfoClsid = uuid.NULL
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.PtrReferentID = 0x020000
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.PtrSizesReferentID = 0x00020004 //0x04, 0x00, 0x02, 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.NULLPointer = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.PtrMaxCount = 0x06
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.PtrPropertyStructGUID = uuid.CLSID_SpecialSystemProperties
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.PtrPropertyStructGUID2 = uuid.CLSID_InstantiationInfo
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.PtrPropertyStructGUID3 = uuid.CLSID_ActivationContextInfo
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.PtrPropertyStructGUID4 = uuid.CLSID_SecurityInfo
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.PtrPropertyStructGUID5 = uuid.CLSID_ServerLocationInfo
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.PtrPropertyStructGUID6 = uuid.CLSID_ScmRequestInfo
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.SizesPtrMaxCount = 0x06
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.SizesPtrPropertyDataSize = 0x68
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.SizesPtrPropertyDataSize2 = 0x58
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.SizesPtrPropertyDataSize3 = 0x90
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.SizesPtrPropertyDataSize4 = propDataSize //", packet_property_data_size);
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.SizesPtrPropertyDataSize5 = 0x20
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.CustomHeader.ClsId.SizesPtrPropertyDataSize6 = 0x30
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.CommonHeader = NewCommonHeader1(0x10) // 0xcccccccc00081001 // 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.PrivateHeader = NewPrivateHeader(0x58)
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.SessionID = 0xffffffff
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.RemoteThisSessionID = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.ClientImpersonating = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.PartitionIDPresent = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.DefaultAuthnLevel = 0x02
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.PartitionGUID = uuid.NULL
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.ProcessRequestFlags = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.OriginalClassContext = 0x14
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.Flags = 0x02
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.Reserved = [32]byte{} // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SpecialSystemProperties.UnusedBuffer = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.CommonHeader = NewCommonHeader1(0x10) //0xcccccccc00081001 //0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.PrivateHeader = NewPrivateHeader(0x48)
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.InstantiatedObjectClsId = uuid.CLSID_WMIAppID
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.ClassContext = 0x14
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.ActivationFlags = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.FlagsSurrogate = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.InterfaceIdCount = 0x01
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.InstantiationFlag = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.InterfaceIdsPtr = 0x0200
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.EntirePropertySize = 0x58
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.VersionMajor = 0x05
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.VersionMinor = 0x07
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.InterfaceIdsMaxCount = 0x01
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.InterfaceIds = uuid.CLSID_WbemLevel1Login
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.InstantiationInfo.UnusedBuffer = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.CommonHeader = NewCommonHeader1(0x10) // 0xcccccccc00081001 // 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.PrivateHeader = NewPrivateHeader(0x80)
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientOk = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.Reserved = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.Reserved2 = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.Reserved3 = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientPtrReferentID = 0x0200
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.NULLPtr = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientPtrClientContextUnknown = 0x60
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientPtrClientContextCntData = 0x60
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientPtrClientContextOBJREFSignature = 0x574f454d // 0x4d, 0x45, 0x4f, 0x57
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientPtrClientContextOBJREFFlags = 0x04
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientPtrClientContextOBJREFIID = uuid.IID_IContext
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientPtrClientContextOBJREFCUSTOMOBJREFCLSID = uuid.CLSID_ContextMarshaler
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.ClientPtrClientContextOBJREFCUSTOMOBJREFSize = 0x30
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ActivationContextInfo.UnusedBuffer = [48]byte{0x01, 0x00, 0x01, 0x00, 0x63, 0x2c, 0x80, 0x2a, 0xa5, 0xd2, 0xaf, 0xdd, 0x4d, 0xc4, 0xbb, 0x37, 0x4d, 0x37, 0x76, 0xd7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.CommonHeader = NewCommonHeader1(0x10)        // 0xcccccccc00081001 // 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.PrivateHeader = NewPrivateHeader(privHeader) //", packet_private_header);
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.AuthenticationFlags = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoPtrReferentID = 0x0200
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.NULLPtr = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoServerInfoReserved = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoServerInfoNameReferentID = 0x00020004 // 0x04, 0x00, 0x02, 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoServerInfoNULLPtr = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoServerInfoReserved2 = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoServerInfoNameMaxCount = targetL // ", packet_target_length);
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoServerInfoNameOffset = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoServerInfoNameActualCount = targetL               //", packet_target_length);
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoServerInfoNameString = make([]byte, len(targetB)) //", packet_target_unicode);
	copy(r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.SecurityInfo.ServerInfoServerInfoNameString[:], targetB)
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.LocationInfo.CommonHeader = NewCommonHeader1(0x10)  //0xcccccccc00081001  //0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.LocationInfo.PrivateHeader = NewPrivateHeader(0x10) //0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.LocationInfo.NULLPtr = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.LocationInfo.ProcessID = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.LocationInfo.ApartmentID = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.LocationInfo.ContextID = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.CommonHeader = NewCommonHeader1(0x10) // 0xcccccccc00081001 // 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.PrivateHeader = NewPrivateHeader(0x20)
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.NULLPtr = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.RemoteRequestPtrReferentID = 0x0200
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.RemoteRequestPtrRemoteRequestClientImpersonationLevel = 0x02
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.RemoteRequestPtrRemoteRequestNumProtocolSequences = 0x01
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.RemoteRequestPtrRemoteRequestUnknown = 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.RemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID = 0x00020004 // 0x04, 0x00, 0x02, 0x00
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.RemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount = 0x01
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.RemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq = 0x07
	r.IActProperties.OBJREF.CUSTOMOBJREF.IActProperties.Properties.ScmRequestInfo.UnusedBuffer = [6]byte{}
	return r
}

func (p PacketDCOMRemoteInstance) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p.DCOMORPCThis)
	binary.Write(&buff, binary.LittleEndian, p.Unknown2)
	binary.Write(&buff, binary.LittleEndian, p.Unknown3)
	binary.Write(&buff, binary.LittleEndian, p.Unknown4)
	binary.Write(&buff, binary.LittleEndian, p.IActProperties.Bytes())
	return buff.Bytes()
}

func (i IActProperties) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, i.CntData)
	binary.Write(&buff, binary.LittleEndian, i.OBJREF.Signature)
	binary.Write(&buff, binary.LittleEndian, i.OBJREF.Flags)
	binary.Write(&buff, binary.LittleEndian, i.OBJREF.IID)
	binary.Write(&buff, binary.LittleEndian, i.OBJREF.CUSTOMOBJREF.Bytes())

	return buff.Bytes()
}

func (i CUSTOMOBJREF) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, i.CLSID)
	binary.Write(&buff, binary.LittleEndian, i.CBExtension)
	binary.Write(&buff, binary.LittleEndian, i.Size)
	binary.Write(&buff, binary.LittleEndian, i.IActProperties.Bytes())

	return buff.Bytes()
}

func (i IActProperties2) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, i.TotalSize)
	binary.Write(&buff, binary.LittleEndian, i.Reserved)
	binary.Write(&buff, binary.LittleEndian, i.CustomHeader)
	binary.Write(&buff, binary.LittleEndian, i.Properties.SpecialSystemProperties)
	binary.Write(&buff, binary.LittleEndian, i.Properties.InstantiationInfo)
	binary.Write(&buff, binary.LittleEndian, i.Properties.ActivationContextInfo)
	binary.Write(&buff, binary.LittleEndian, i.Properties.SecurityInfo.Bytes())
	binary.Write(&buff, binary.LittleEndian, i.Properties.LocationInfo)
	binary.Write(&buff, binary.LittleEndian, i.Properties.ScmRequestInfo)

	return buff.Bytes()
}

func (i SecurityInfo) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, i.CommonHeader)
	binary.Write(&buff, binary.LittleEndian, i.PrivateHeader)
	binary.Write(&buff, binary.LittleEndian, i.AuthenticationFlags)
	binary.Write(&buff, binary.LittleEndian, i.ServerInfoPtrReferentID)
	binary.Write(&buff, binary.LittleEndian, i.NULLPtr)
	binary.Write(&buff, binary.LittleEndian, i.ServerInfoServerInfoReserved)
	binary.Write(&buff, binary.LittleEndian, i.ServerInfoServerInfoNameReferentID)
	binary.Write(&buff, binary.LittleEndian, i.ServerInfoServerInfoNULLPtr)
	binary.Write(&buff, binary.LittleEndian, i.ServerInfoServerInfoReserved2)
	binary.Write(&buff, binary.LittleEndian, i.ServerInfoServerInfoNameMaxCount)
	binary.Write(&buff, binary.LittleEndian, i.ServerInfoServerInfoNameOffset)
	binary.Write(&buff, binary.LittleEndian, i.ServerInfoServerInfoNameActualCount)
	binary.Write(&buff, binary.LittleEndian, i.ServerInfoServerInfoNameString)
	return buff.Bytes()
}

type PacketDCOMRemQueryInterface struct {
	VersionMajor uint16
	VersionMinor uint16
	Flags        uint32
	Reserved     uint32
	CausalityID  [16]byte
	Reserved2    uint32
	IPID         [16]byte
	Refs         uint32
	IIDs         uint16
	Unknown      [6]byte
	IID          [16]byte
}

func NewPacketDCOMRemQueryInterface(causalityID, IPID, IID []byte) PacketDCOMRemQueryInterface {
	r := PacketDCOMRemQueryInterface{
		VersionMajor: 5,
		VersionMinor: 7,
		Flags:        0,
		Reserved:     0,
		//CausalityID:
		Reserved2: 0,
		//IPID:
		Refs:    5,
		IIDs:    1,
		Unknown: [6]byte{0, 0, 1, 0, 0, 0},
	}
	copy(r.CausalityID[:], causalityID)
	copy(r.IPID[:], IPID)
	copy(r.IID[:], IID)
	return r
}

func (p PacketDCOMRemQueryInterface) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p)
	return buff.Bytes()
}

type PacketDCOMMemRelease struct {
	VersionMajor  uint16
	VersionMinor  uint16
	Flags         uint32
	Reserved      uint32
	CausalityID   [16]byte
	Reserved2     uint32
	Unknown       uint32
	InterfaceRefs uint32
	IPID          [16]byte
	PublicRefs    uint32
	PrivateRefs   uint32
	packetIPID2   [16]byte
	PublicRefs2   uint32
	PrivateRefs2  uint32
}

func NewPacketDCOMMemRelease(causality, ipid, ipid2 []byte) PacketDCOMMemRelease {
	r := PacketDCOMMemRelease{
		VersionMajor: 0x05,
		VersionMinor: 0x07,
		Flags:        0x00,
		Reserved:     0x00,
		//CausalityID:  packet_causality_ID);
		Reserved2:     0x00,
		Unknown:       0x02,
		InterfaceRefs: 0x02,
		//IPID:  packet_IPID);
		PublicRefs:  0x05,
		PrivateRefs: 0x00,
		//packet_IPID2:  packet_IPID2);
		PublicRefs2:  0x05,
		PrivateRefs2: 0x00,
	}

	copy(r.CausalityID[:], causality)
	copy(r.IPID[:], ipid)
	copy(r.packetIPID2[:], ipid2)

	return r
}

func (p PacketDCOMMemRelease) Bytes() []byte {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.LittleEndian, p)
	return buff.Bytes()
}

type DCOMOXIDResolver struct {
	VersionMajor     uint16
	VersionMinor     uint16
	Unknown          [8]byte
	NumEntries       uint16
	SecurityOffset   uint16
	StringBindings   []DCOMStringBinding
	SecurityBindings []DCOMSecurityBinding
	Unknown2         [8]byte
}

type DCOMSecurityBinding struct {
	AuthnSvc  uint16
	AuthzSvc  uint16
	PrincName []byte
}

type DCOMStringBinding struct {
	TowerId     uint16
	NetworkAddr []byte
}

func NewDCOMOXIDResolver(b []byte) DCOMOXIDResolver {
	r := DCOMOXIDResolver{}
	cursor := 0
	r.VersionMajor = binary.LittleEndian.Uint16(b[cursor : cursor+2])
	cursor += 2
	r.VersionMajor = binary.LittleEndian.Uint16(b[cursor : cursor+2])
	cursor += 2
	copy(r.Unknown[:], b[cursor:cursor+8])
	cursor += 8

	r.NumEntries = binary.LittleEndian.Uint16(b[cursor : cursor+2])
	cursor += 2
	r.SecurityOffset = binary.LittleEndian.Uint16(b[cursor : cursor+2])
	cursor += 2

	for !bytes.HasPrefix(b[cursor:], []byte{0, 0}) {
		newBind := DCOMStringBinding{}
		newBind.TowerId = binary.LittleEndian.Uint16(b[cursor : cursor+2])
		cursor += 2
		//yep, scan to double null top kek
		if bytes.HasPrefix(b[cursor:], []byte{0, 0}) {
			newBind.NetworkAddr = []byte{0, 0}
			cursor += 2
		} else {
			end := bytes.Index(b[cursor:], []byte{0, 0, 0})
			newBind.NetworkAddr = b[cursor : end+cursor+1]
			cursor += end + 3
		}
		r.StringBindings = append(r.StringBindings, newBind)
	}
	cursor += 2

	for !bytes.HasPrefix(b[cursor:], []byte{0, 0}) {
		newBind := DCOMSecurityBinding{}
		newBind.AuthnSvc = binary.LittleEndian.Uint16(b[cursor : cursor+2])
		cursor += 2
		newBind.AuthzSvc = binary.LittleEndian.Uint16(b[cursor : cursor+2])
		cursor += 2
		//yep, scan to double null top kek
		if bytes.HasPrefix(b[cursor:], []byte{0, 0}) {
			newBind.PrincName = []byte{0, 0}
			cursor += 2
		} else {
			end := bytes.Index(b[cursor:], []byte{0, 0, 0})
			newBind.PrincName = b[cursor : end+cursor]
			cursor += end + 1
		}
		r.SecurityBindings = append(r.SecurityBindings, newBind)
	}
	cursor += 2

	return r
}
