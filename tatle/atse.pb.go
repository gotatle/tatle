// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: atse.proto

package tatle

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type DEMCiphertext struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Nonce []byte `protobuf:"bytes,1,opt,name=nonce,proto3" json:"nonce,omitempty"`
	Ctxt  []byte `protobuf:"bytes,2,opt,name=ctxt,proto3" json:"ctxt,omitempty"`
}

func (x *DEMCiphertext) Reset() {
	*x = DEMCiphertext{}
	if protoimpl.UnsafeEnabled {
		mi := &file_atse_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DEMCiphertext) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DEMCiphertext) ProtoMessage() {}

func (x *DEMCiphertext) ProtoReflect() protoreflect.Message {
	mi := &file_atse_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DEMCiphertext.ProtoReflect.Descriptor instead.
func (*DEMCiphertext) Descriptor() ([]byte, []int) {
	return file_atse_proto_rawDescGZIP(), []int{0}
}

func (x *DEMCiphertext) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

func (x *DEMCiphertext) GetCtxt() []byte {
	if x != nil {
		return x.Ctxt
	}
	return nil
}

type AtseCiphertext struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Gid     []byte `protobuf:"bytes,1,opt,name=gid,proto3" json:"gid,omitempty"`
	Mid     []byte `protobuf:"bytes,2,opt,name=mid,proto3" json:"mid,omitempty"`
	Demctxt []byte `protobuf:"bytes,3,opt,name=demctxt,proto3" json:"demctxt,omitempty"`
}

func (x *AtseCiphertext) Reset() {
	*x = AtseCiphertext{}
	if protoimpl.UnsafeEnabled {
		mi := &file_atse_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AtseCiphertext) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AtseCiphertext) ProtoMessage() {}

func (x *AtseCiphertext) ProtoReflect() protoreflect.Message {
	mi := &file_atse_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AtseCiphertext.ProtoReflect.Descriptor instead.
func (*AtseCiphertext) Descriptor() ([]byte, []int) {
	return file_atse_proto_rawDescGZIP(), []int{1}
}

func (x *AtseCiphertext) GetGid() []byte {
	if x != nil {
		return x.Gid
	}
	return nil
}

func (x *AtseCiphertext) GetMid() []byte {
	if x != nil {
		return x.Mid
	}
	return nil
}

func (x *AtseCiphertext) GetDemctxt() []byte {
	if x != nil {
		return x.Demctxt
	}
	return nil
}

type KeyMaterialPb struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id   uint64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	KeyX []byte `protobuf:"bytes,2,opt,name=keyX,proto3" json:"keyX,omitempty"`
	KeyY []byte `protobuf:"bytes,3,opt,name=keyY,proto3" json:"keyY,omitempty"`
	Rnd  []byte `protobuf:"bytes,4,opt,name=rnd,proto3" json:"rnd,omitempty"`
}

func (x *KeyMaterialPb) Reset() {
	*x = KeyMaterialPb{}
	if protoimpl.UnsafeEnabled {
		mi := &file_atse_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyMaterialPb) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyMaterialPb) ProtoMessage() {}

func (x *KeyMaterialPb) ProtoReflect() protoreflect.Message {
	mi := &file_atse_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyMaterialPb.ProtoReflect.Descriptor instead.
func (*KeyMaterialPb) Descriptor() ([]byte, []int) {
	return file_atse_proto_rawDescGZIP(), []int{2}
}

func (x *KeyMaterialPb) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *KeyMaterialPb) GetKeyX() []byte {
	if x != nil {
		return x.KeyX
	}
	return nil
}

func (x *KeyMaterialPb) GetKeyY() []byte {
	if x != nil {
		return x.KeyY
	}
	return nil
}

func (x *KeyMaterialPb) GetRnd() []byte {
	if x != nil {
		return x.Rnd
	}
	return nil
}

type SchnorrProofPb struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	C  []byte `protobuf:"bytes,1,opt,name=c,proto3" json:"c,omitempty"`
	U0 []byte `protobuf:"bytes,2,opt,name=u0,proto3" json:"u0,omitempty"`
	U1 []byte `protobuf:"bytes,3,opt,name=u1,proto3" json:"u1,omitempty"`
}

func (x *SchnorrProofPb) Reset() {
	*x = SchnorrProofPb{}
	if protoimpl.UnsafeEnabled {
		mi := &file_atse_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SchnorrProofPb) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SchnorrProofPb) ProtoMessage() {}

func (x *SchnorrProofPb) ProtoReflect() protoreflect.Message {
	mi := &file_atse_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SchnorrProofPb.ProtoReflect.Descriptor instead.
func (*SchnorrProofPb) Descriptor() ([]byte, []int) {
	return file_atse_proto_rawDescGZIP(), []int{3}
}

func (x *SchnorrProofPb) GetC() []byte {
	if x != nil {
		return x.C
	}
	return nil
}

func (x *SchnorrProofPb) GetU0() []byte {
	if x != nil {
		return x.U0
	}
	return nil
}

func (x *SchnorrProofPb) GetU1() []byte {
	if x != nil {
		return x.U1
	}
	return nil
}

type RPCResponsePb struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id    []byte `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Point []byte `protobuf:"bytes,2,opt,name=point,proto3" json:"point,omitempty"`
	Proof []byte `protobuf:"bytes,3,opt,name=proof,proto3" json:"proof,omitempty"`
}

func (x *RPCResponsePb) Reset() {
	*x = RPCResponsePb{}
	if protoimpl.UnsafeEnabled {
		mi := &file_atse_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RPCResponsePb) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RPCResponsePb) ProtoMessage() {}

func (x *RPCResponsePb) ProtoReflect() protoreflect.Message {
	mi := &file_atse_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RPCResponsePb.ProtoReflect.Descriptor instead.
func (*RPCResponsePb) Descriptor() ([]byte, []int) {
	return file_atse_proto_rawDescGZIP(), []int{4}
}

func (x *RPCResponsePb) GetId() []byte {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *RPCResponsePb) GetPoint() []byte {
	if x != nil {
		return x.Point
	}
	return nil
}

func (x *RPCResponsePb) GetProof() []byte {
	if x != nil {
		return x.Proof
	}
	return nil
}

type BatchedRPCResponsePb struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Responses []*RPCResponsePb `protobuf:"bytes,1,rep,name=responses,proto3" json:"responses,omitempty"`
}

func (x *BatchedRPCResponsePb) Reset() {
	*x = BatchedRPCResponsePb{}
	if protoimpl.UnsafeEnabled {
		mi := &file_atse_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BatchedRPCResponsePb) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BatchedRPCResponsePb) ProtoMessage() {}

func (x *BatchedRPCResponsePb) ProtoReflect() protoreflect.Message {
	mi := &file_atse_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BatchedRPCResponsePb.ProtoReflect.Descriptor instead.
func (*BatchedRPCResponsePb) Descriptor() ([]byte, []int) {
	return file_atse_proto_rawDescGZIP(), []int{5}
}

func (x *BatchedRPCResponsePb) GetResponses() []*RPCResponsePb {
	if x != nil {
		return x.Responses
	}
	return nil
}

// pp = (p, g, h, G, H, H', y1,...,yn) in DiSE
// pp =  (p, G2.g, G2.h, GT.g, GT.h, G2, GT, H, H2, HT, y1,...,yn) in AmorTiSE
// implementation uses implicit parameters p, G2, GT, H, H2, HT via constants or code
// so we save (G2.g, G2.h, GT.g, GT.h, G2.[y1,...,yn], GT.[y1,...,yn])
type PublicParamsPb struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	T             uint64   `protobuf:"varint,1,opt,name=t,proto3" json:"t,omitempty"`
	N             uint64   `protobuf:"varint,2,opt,name=n,proto3" json:"n,omitempty"`
	GeneratorG2G  []byte   `protobuf:"bytes,3,opt,name=generatorG2g,proto3" json:"generatorG2g,omitempty"`
	GeneratorG2H  []byte   `protobuf:"bytes,4,opt,name=generatorG2h,proto3" json:"generatorG2h,omitempty"`
	GeneratorGTg  []byte   `protobuf:"bytes,5,opt,name=generatorGTg,proto3" json:"generatorGTg,omitempty"`
	GeneratorGTh  []byte   `protobuf:"bytes,6,opt,name=generatorGTh,proto3" json:"generatorGTh,omitempty"`
	CommitmentsG2 [][]byte `protobuf:"bytes,7,rep,name=commitmentsG2,proto3" json:"commitmentsG2,omitempty"`
	CommitmentsGT [][]byte `protobuf:"bytes,8,rep,name=commitmentsGT,proto3" json:"commitmentsGT,omitempty"`
}

func (x *PublicParamsPb) Reset() {
	*x = PublicParamsPb{}
	if protoimpl.UnsafeEnabled {
		mi := &file_atse_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublicParamsPb) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicParamsPb) ProtoMessage() {}

func (x *PublicParamsPb) ProtoReflect() protoreflect.Message {
	mi := &file_atse_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicParamsPb.ProtoReflect.Descriptor instead.
func (*PublicParamsPb) Descriptor() ([]byte, []int) {
	return file_atse_proto_rawDescGZIP(), []int{6}
}

func (x *PublicParamsPb) GetT() uint64 {
	if x != nil {
		return x.T
	}
	return 0
}

func (x *PublicParamsPb) GetN() uint64 {
	if x != nil {
		return x.N
	}
	return 0
}

func (x *PublicParamsPb) GetGeneratorG2G() []byte {
	if x != nil {
		return x.GeneratorG2G
	}
	return nil
}

func (x *PublicParamsPb) GetGeneratorG2H() []byte {
	if x != nil {
		return x.GeneratorG2H
	}
	return nil
}

func (x *PublicParamsPb) GetGeneratorGTg() []byte {
	if x != nil {
		return x.GeneratorGTg
	}
	return nil
}

func (x *PublicParamsPb) GetGeneratorGTh() []byte {
	if x != nil {
		return x.GeneratorGTh
	}
	return nil
}

func (x *PublicParamsPb) GetCommitmentsG2() [][]byte {
	if x != nil {
		return x.CommitmentsG2
	}
	return nil
}

func (x *PublicParamsPb) GetCommitmentsGT() [][]byte {
	if x != nil {
		return x.CommitmentsGT
	}
	return nil
}

var File_atse_proto protoreflect.FileDescriptor

var file_atse_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x61, 0x74, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x61, 0x74,
	0x73, 0x65, 0x22, 0x39, 0x0a, 0x0d, 0x44, 0x45, 0x4d, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74,
	0x65, 0x78, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x74, 0x78,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x63, 0x74, 0x78, 0x74, 0x22, 0x4e, 0x0a,
	0x0e, 0x41, 0x74, 0x73, 0x65, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x12,
	0x10, 0x0a, 0x03, 0x67, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x67, 0x69,
	0x64, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x6d, 0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x65, 0x6d, 0x63, 0x74, 0x78, 0x74, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x64, 0x65, 0x6d, 0x63, 0x74, 0x78, 0x74, 0x22, 0x59, 0x0a,
	0x0d, 0x4b, 0x65, 0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x50, 0x62, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12,
	0x0a, 0x04, 0x6b, 0x65, 0x79, 0x58, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x6b, 0x65,
	0x79, 0x58, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x65, 0x79, 0x59, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x6b, 0x65, 0x79, 0x59, 0x12, 0x10, 0x0a, 0x03, 0x72, 0x6e, 0x64, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x03, 0x72, 0x6e, 0x64, 0x22, 0x3e, 0x0a, 0x0e, 0x53, 0x63, 0x68, 0x6e,
	0x6f, 0x72, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x50, 0x62, 0x12, 0x0c, 0x0a, 0x01, 0x63, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x63, 0x12, 0x0e, 0x0a, 0x02, 0x75, 0x30, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x75, 0x30, 0x12, 0x0e, 0x0a, 0x02, 0x75, 0x31, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x75, 0x31, 0x22, 0x4b, 0x0a, 0x0d, 0x52, 0x50, 0x43, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x50, 0x62, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x12,
	0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x49, 0x0a, 0x14, 0x42, 0x61, 0x74, 0x63, 0x68, 0x65, 0x64,
	0x52, 0x50, 0x43, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x50, 0x62, 0x12, 0x31, 0x0a,
	0x09, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x13, 0x2e, 0x61, 0x74, 0x73, 0x65, 0x2e, 0x52, 0x50, 0x43, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x50, 0x62, 0x52, 0x09, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x73,
	0x22, 0x88, 0x02, 0x0a, 0x0e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x50, 0x61, 0x72, 0x61, 0x6d,
	0x73, 0x50, 0x62, 0x12, 0x0c, 0x0a, 0x01, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x01,
	0x74, 0x12, 0x0c, 0x0a, 0x01, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x01, 0x6e, 0x12,
	0x22, 0x0a, 0x0c, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x47, 0x32, 0x67, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72,
	0x47, 0x32, 0x67, 0x12, 0x22, 0x0a, 0x0c, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72,
	0x47, 0x32, 0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x67, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x6f, 0x72, 0x47, 0x32, 0x68, 0x12, 0x22, 0x0a, 0x0c, 0x67, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x6f, 0x72, 0x47, 0x54, 0x67, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x67,
	0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x47, 0x54, 0x67, 0x12, 0x22, 0x0a, 0x0c, 0x67,
	0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x47, 0x54, 0x68, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x0c, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x47, 0x54, 0x68, 0x12,
	0x24, 0x0a, 0x0d, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x47, 0x32,
	0x18, 0x07, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x73, 0x47, 0x32, 0x12, 0x24, 0x0a, 0x0d, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d,
	0x65, 0x6e, 0x74, 0x73, 0x47, 0x54, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x63, 0x6f,
	0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x47, 0x54, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_atse_proto_rawDescOnce sync.Once
	file_atse_proto_rawDescData = file_atse_proto_rawDesc
)

func file_atse_proto_rawDescGZIP() []byte {
	file_atse_proto_rawDescOnce.Do(func() {
		file_atse_proto_rawDescData = protoimpl.X.CompressGZIP(file_atse_proto_rawDescData)
	})
	return file_atse_proto_rawDescData
}

var file_atse_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_atse_proto_goTypes = []interface{}{
	(*DEMCiphertext)(nil),        // 0: atse.DEMCiphertext
	(*AtseCiphertext)(nil),       // 1: atse.AtseCiphertext
	(*KeyMaterialPb)(nil),        // 2: atse.KeyMaterialPb
	(*SchnorrProofPb)(nil),       // 3: atse.SchnorrProofPb
	(*RPCResponsePb)(nil),        // 4: atse.RPCResponsePb
	(*BatchedRPCResponsePb)(nil), // 5: atse.BatchedRPCResponsePb
	(*PublicParamsPb)(nil),       // 6: atse.PublicParamsPb
}
var file_atse_proto_depIdxs = []int32{
	4, // 0: atse.BatchedRPCResponsePb.responses:type_name -> atse.RPCResponsePb
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_atse_proto_init() }
func file_atse_proto_init() {
	if File_atse_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_atse_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DEMCiphertext); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_atse_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AtseCiphertext); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_atse_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyMaterialPb); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_atse_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SchnorrProofPb); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_atse_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RPCResponsePb); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_atse_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BatchedRPCResponsePb); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_atse_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublicParamsPb); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_atse_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_atse_proto_goTypes,
		DependencyIndexes: file_atse_proto_depIdxs,
		MessageInfos:      file_atse_proto_msgTypes,
	}.Build()
	File_atse_proto = out.File
	file_atse_proto_rawDesc = nil
	file_atse_proto_goTypes = nil
	file_atse_proto_depIdxs = nil
}
