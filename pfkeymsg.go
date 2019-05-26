package pfkey

import (
	"fmt"

	"github.com/FranGM/simplelog"
)

func (p *Msg) String() string {
	var s string
	s += fmt.Sprintf("%+v", p.Msg)

	if p.HasSA() {
		s += fmt.Sprintf("%+v", p.Extensions.SA)
	}

	if p.HasLifetimeCurrent() {
		s += fmt.Sprintf("%+v", p.Extensions.LifetimeCurrent)
	}

	if p.HasLifetimeHard() {
		s += fmt.Sprintf("%+v", p.Extensions.LifetimeHard)
	}

	if p.HasLifetimeSoft() {
		s += fmt.Sprintf("%+v", p.Extensions.LifetimeSoft)
	}

	if p.HasAddressSrc() {
		s += fmt.Sprintf("%+v %+v", p.Extensions.AddressSrc, p.Extensions.SockAddrSrc)
	}

	if p.HasAddressDst() {
		s += fmt.Sprintf("%+v %+v", p.Extensions.AddressDst, p.Extensions.SockAddrDst)
	}

	if p.HasAuthKey() {
		s += fmt.Sprintf("%+v", p.Extensions.AuthKey)
	}

	if p.HasEncryptKey() {
		s += fmt.Sprintf("%+v", p.Extensions.EncryptKey)
	}

	if p.HasSPIRange() {
		s += fmt.Sprintf("%+v", p.Extensions.SPIRange)
	}

	if p.Present.Proposal {
		s += fmt.Sprintf("%+v", p.Extensions.Proposal)
	}

	if p.Present.XPolicy {
		s += fmt.Sprintf("%+v", p.Extensions.XPolicy)
	}

	return s
}

func (p *Msg) writeToBuffer(buf *msgBuffer) error {

	// TODO: Automatically set message length here
	// TODO: This method might need actual error checking

	buf.writeStruct(p.Msg)

	if p.HasSA() {
		buf.writeStruct(p.Extensions.SA)
	}

	if p.HasLifetimeCurrent() {
		buf.writeStruct(p.Extensions.LifetimeCurrent)
	}

	if p.HasLifetimeHard() {
		buf.writeStruct(p.Extensions.LifetimeHard)
	}

	if p.HasLifetimeSoft() {
		buf.writeStruct(p.Extensions.LifetimeSoft)
	}

	if p.HasAddressSrc() {
		buf.writeStruct(p.Extensions.AddressSrc)
		buf.writeStruct(p.Extensions.SockAddrSrc)
	}

	if p.HasAddressDst() {
		buf.writeStruct(p.Extensions.AddressDst)
		buf.writeStruct(p.Extensions.SockAddrDst)
	}

	if p.HasAuthKey() {
		buf.writeStruct(p.Extensions.AuthKey)
		if p.Extensions.AuthKey.Len > 1 {
			buf.writeBytes(p.Extensions.AuthKeyBits)
		}
	}

	if p.HasEncryptKey() {
		buf.writeStruct(p.Extensions.EncryptKey)
		if p.Extensions.EncryptKey.Len > 1 {
			buf.writeBytes(p.Extensions.EncryptKeyBits)
		}
	}

	if p.HasSPIRange() {
		buf.writeStruct(p.Extensions.SPIRange)
	}

	if p.Present.Proposal {
		simplelog.Fatal.Println("Writing of proposal is not implemented")
	}

	if p.Present.XPolicy {
		simplelog.Fatal.Println("Writing of XPolicy is not implemented")
	}

	return nil
}

// setMsgLen sets the Len field of the message to the appropriate size
// considering all the extensions present.
func (p *Msg) setMsgLen() {
	var n uint16

	p.Msg.Version = PF_KEY_V2

	// TODO: Are we missing sadb_supported here? (and maybe others)

	if p.HasSA() {
		n += p.Extensions.SA.Len
	}

	if p.HasLifetimeCurrent() {
		n += p.Extensions.LifetimeCurrent.Len
	}

	if p.HasLifetimeHard() {
		n += p.Extensions.LifetimeHard.Len
	}

	if p.HasLifetimeSoft() {
		n += p.Extensions.LifetimeSoft.Len
	}

	if p.HasAddressSrc() {
		n += p.Extensions.AddressSrc.Len
	}

	if p.HasAddressDst() {
		n += p.Extensions.AddressDst.Len
	}

	// TODO: Move setting the exttype/len to its own method
	if p.Present.Proposal {
		p.Extensions.Proposal.ExtType = SADB_EXT_PROPOSAL
		combLen := uint16(len(p.Extensions.ProposalCombs) * SADBCOMB_LEN)
		p.Extensions.Proposal.Len = SADBPROP_LEN + combLen
		n += p.Extensions.Proposal.Len
	}

	if p.HasAuthKey() {
		n += p.Extensions.AuthKey.Len
	}

	if p.HasEncryptKey() {
		n += p.Extensions.EncryptKey.Len
	}

	if p.HasSPIRange() {
		n += p.Extensions.SPIRange.Len
	}

	// TODO: Move setting the exttype/len to its own method
	if p.Present.XPolicy {
		p.Extensions.XPolicy.ExtType = SADB_X_EXT_POLICY
		p.Extensions.XPolicy.Len = SADBXPOLICY_LEN
		n += p.Extensions.XPolicy.Len
	}

	// Add the size of the base message to the size of all the extensions
	p.Msg.Len = n + SADBMSG_LEN
}

// SetSA sets the value for the SA extension on this PFKEYMsg
func (p *Msg) SetSA(sa SADBSA) {
	p.Extensions.SA = sa
	p.Extensions.SA.ExtType = SADB_EXT_SA
	p.Extensions.SA.Len = SADBSA_LEN

	p.Present.SA = true
}

// HasSA returns true if this PFKEYMsg has the SadbSA extension present.
func (p *Msg) HasSA() bool {
	return p.Present.SA
}

// SetLifetimeCurrent sets the value for the LifetimeCurrent extension on this PFKEYMsg
func (p *Msg) SetLifetimeCurrent(lt SADBLifetime) {
	p.Extensions.LifetimeCurrent = lt
	p.Extensions.LifetimeCurrent.ExtType = SADB_EXT_LIFETIME_CURRENT
	p.Extensions.LifetimeCurrent.Len = SADBLIFETIME_LEN

	p.Present.LifetimeCurrent = true
}

// HasLifetimeCurrent returns true if this PFKEYMsg has the LifetimeCurrent extension present.
func (p *Msg) HasLifetimeCurrent() bool {
	return p.Present.LifetimeCurrent
}

// SetLifetimeHard sets the value for the LifetimeHard extension on this PFKEYMsg
func (p *Msg) SetLifetimeHard(lt SADBLifetime) {
	p.Extensions.LifetimeHard = lt
	p.Extensions.LifetimeHard.ExtType = SADB_EXT_LIFETIME_HARD
	p.Extensions.LifetimeHard.Len = SADBLIFETIME_LEN

	p.Present.LifetimeHard = true
}

// HasLifetimeHard returns true if this PFKEYMsg has the LifetimeHard extension present.
func (p *Msg) HasLifetimeHard() bool {
	return p.Present.LifetimeHard
}

// SetLifetimeSoft sets the value for the LifetimeSoft extension on this PFKEYMsg
func (p *Msg) SetLifetimeSoft(lt SADBLifetime) {
	p.Extensions.LifetimeSoft = lt
	p.Extensions.LifetimeSoft.ExtType = SADB_EXT_LIFETIME_SOFT
	p.Extensions.LifetimeSoft.Len = SADBLIFETIME_LEN

	p.Present.LifetimeSoft = true
}

// HasLifetimeSoft returns true if this PFKEYMsg has the LifetimeSoft extension present.
func (p *Msg) HasLifetimeSoft() bool {
	return p.Present.LifetimeSoft
}

// SetAddressSrc sets the value for the AddressSrc extension on this PFKEYMsg
func (p *Msg) SetAddressSrc(src Node) {
	// TODO: This needs to change when we support other sockaddr structures (for IPv6 for example)
	p.Extensions.AddressSrc = SADBAddress{
		Proto:     0,
		PrefixLen: 32,
	}
	p.Extensions.SockAddrSrc = src.buildSockAddr()
	p.Extensions.AddressSrc.ExtType = SADB_EXT_ADDRESS_SRC
	p.Extensions.AddressSrc.Len = SADBADDRESS_LEN + SOCKADDRIN_LEN

	p.Present.AddressSrc = true
}

// HasAddressSrc returns true if this PFKEYMsg has the AddressSrc extension present.
func (p *Msg) HasAddressSrc() bool {
	return p.Present.AddressSrc
}

// SetAddressDst sets the value for the AddressDst extension on this PFKEYMsg
func (p *Msg) SetAddressDst(dst Node) {
	// TODO: This needs to change when we support other sockaddr structures (for IPv6 for example)
	p.Extensions.AddressDst = SADBAddress{
		Proto:     0,
		PrefixLen: 32,
	}
	p.Extensions.SockAddrDst = dst.buildSockAddr()
	p.Extensions.AddressDst.ExtType = SADB_EXT_ADDRESS_DST
	p.Extensions.AddressDst.Len = SADBADDRESS_LEN + SOCKADDRIN_LEN

	p.Present.AddressDst = true
}

// HasAddressDst returns true if this PFKEYMsg has the AddressDst extension present.
func (p *Msg) HasAddressDst() bool {
	return p.Present.AddressDst
}

// SetAuthKey builds the SADB_EXT_KEY_AUTH extension for this PFKEYMsg.
func (p *Msg) SetAuthKey(key []byte, keySize int) {
	p.Extensions.AuthKey = SADBKey{
		Bits:    uint16(keySize),
		ExtType: SADB_EXT_KEY_AUTH,
		Len:     SADBKEY_LEN + uint16(len(key)/WORD_SIZE),
	}
	p.Extensions.AuthKeyBits = key
	p.Present.AuthKey = true
}

// HasAuthKey returns true if this PFKEYMsg has the AuthKey extension present.
func (p *Msg) HasAuthKey() bool {
	return p.Present.AuthKey
}

// SetEncryptKey builds the SADB_EXT_KEY_ENCRYPT extension for this PFKEYMsg
func (p *Msg) SetEncryptKey(key []byte, keySize int) {
	p.Extensions.EncryptKey = SADBKey{
		Bits:    uint16(keySize),
		ExtType: SADB_EXT_KEY_ENCRYPT,
		Len:     SADBKEY_LEN + uint16(len(key)/WORD_SIZE),
	}
	p.Extensions.EncryptKeyBits = key
	p.Present.EncryptKey = true
}

// HasEncryptKey returns true if this PFKEYMsg has the EncryptKey extension present.
func (p *Msg) HasEncryptKey() bool {
	return p.Present.EncryptKey
}

// SetSPIRANGE adds the SADBSPIRange extension to this PFKEYMsg
func (p *Msg) SetSPIRANGE(min int, max int) {

	p.Extensions.SPIRange = SADBSPIRange{
		Min:     uint32(min),
		Max:     uint32(max),
		ExtType: SADB_EXT_SPIRANGE,
		Len:     SADBSPIRANGE_LEN,
	}
	p.Present.SPIRange = true
}

// HasSPIRange returns true if this PFKEYMsg has the SPIRange extension.
func (p *Msg) HasSPIRange() bool {
	return p.Present.SPIRange
}

// SetProposal sets the value of the Proposal extension on this PFKEYMsg
func (p *Msg) SetProposal() {
	// XXX TODO Implement
}
