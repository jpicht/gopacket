// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"github.com/jpicht/gopacket"
)

// StpBPDUType defines well-known BPDU types
type StpBPDUType uint8

// StpBPDUTypes
const (
	StpBPDUConfig                     StpBPDUType = 0x00
	StpBPDUTopologyChangeNotification StpBPDUType = 0x80
	StpBPDURSTMSTConfig               StpBPDUType = 0x02
)

func (t StpBPDUType) String() string {
	switch t {
	case StpBPDUConfig:
		return "config"
	case StpBPDUTopologyChangeNotification:
		return "topology change notification"
	case StpBPDURSTMSTConfig:
		return "RST/MST config"
	default:
	}
	return "Unkown STP BPDU type"
}

// STPPortRole defines the port roles
type STPPortRole uint8

// STPPortRole values
const (
	STPPortRoleBackup     STPPortRole = 0x01
	STPPortRoleRool       STPPortRole = 0x02
	STPPortRoleDesignated STPPortRole = 0x03
)

// STPPeerID contains the identity and priority information about an STP peer
type STPPeerID struct {
	Priority          uint8
	SystemIDExtension uint16
	MACAddress        [6]byte
}

// STPFlags implements the stp flag field decoder
type STPFlags struct {
	TopologyChange                bool
	Proposal                      bool
	PortRole                      STPPortRole
	Learning                      bool
	Forwarding                    bool
	Agreement                     bool
	TopologyChangeAcknowledgement bool
}

// StpVersionID specifies the protocol variant
type StpVersionID uint8

// known StpVersionID values
const (
	StpVersionSTP StpVersionID = 0x00
	StpVersionRST StpVersionID = 0x02
	StpVersionMST StpVersionID = 0x03
	StpVersionSPT StpVersionID = 0x04
)

// STP decode spanning tree protocol packets to transport BPDU (bridge protocol data unit) message.
type STP struct {
	BaseLayer
	StpProtocolID [2]byte // always 0x0000
	StpVersionID  StpVersionID
	StpBPDUType   StpBPDUType
	STPFlags      STPFlags
	RootID        STPPeerID
	RootPathCost  uint32
	BridgeID      STPPeerID
}

func (s *STP) decodeSTPFlags(flags uint8) (f STPFlags) {
	f.TopologyChange = flags&0x01 == 0x01
	f.TopologyChangeAcknowledgement = flags&0x80 == 0x80

	if f.TopologyChange {
		return
	}

	if s.StpVersionID == StpVersionSTP {
		return
	}

	f.Proposal = flags&0x02 == 0x02
	f.PortRole = STPPortRole((flags >> 2) & 0x03)
	f.Learning = flags&0x10 == 0x10
	f.Forwarding = flags&0x20 == 0x20
	f.Agreement = flags&0x40 == 0x40

	return
}

func decodeSTPPeerID(raw []byte) *STPPeerID {
	if len(raw) != 8 {
		panic("wrong use of decodeSTPPeerID, pass a byte slice of length 8!")
	}
	p := &STPPeerID{}
	return p
}

// LayerType returns gopacket.LayerTypeSTP.
func (s *STP) LayerType() gopacket.LayerType { return LayerTypeSTP }

func decodeSTP(data []byte, p gopacket.PacketBuilder) error {
	stp := &STP{}
	stp.Contents = data[:]
	stp.StpProtocolID = [2]byte{data[0], data[1]}
	stp.StpVersionID = StpVersionID(data[2])
	stp.StpBPDUType = StpBPDUType(data[3])
	stp.decodeSTPFlags(uint8(data[4]))
	p.AddLayer(stp)
	return nil
}
