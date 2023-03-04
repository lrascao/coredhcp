// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//go:build darwin
// +build darwin

package server

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

func sendEthernet(iface net.Interface, resp *dhcpv4.DHCPv4) error {
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       resp.ClientHWAddr,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    resp.ServerIPAddr,
		DstIP:    resp.YourIPAddr,
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udp := layers.UDP{
		SrcPort: 6667,
		DstPort: 6668,
		// SrcPort: dhcpv4.ServerPort,
		// DstPort: dhcpv4.ClientPort,
	}

	if err := udp.SetNetworkLayerForChecksum(&ip); err != nil {
		return fmt.Errorf("Send Ethernet: Couldn't set network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Decode a packet
	packet := gopacket.NewPacket(resp.ToBytes(), layers.LayerTypeDHCPv4, gopacket.NoCopy)
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	dhcp, ok := dhcpLayer.(gopacket.SerializableLayer)
	if !ok {
		return fmt.Errorf("Layer %s is not serializable", dhcpLayer.LayerType().String())
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, dhcp); err != nil {
		return fmt.Errorf("Cannot serialize layer: %v", err)
	}
	data := buf.Bytes()

	dev, err := newDev(&iface)
	if err != nil {
		return fmt.Errorf("unable to open bpf dev: %w", err)
	}
	defer dev.Close()

	if _, err := dev.fd.Write(data); err != nil {
		return fmt.Errorf("unable to write to bpf dev: %w", err)
	}

	return nil
}

func getBpfFd() (*os.File, string, error) {
	for i := 0; i < 99; i++ {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		if file, err := os.OpenFile(dev, os.O_RDWR, 0); err == nil {
			return file, dev, nil
		}
	}

	return nil, "", fmt.Errorf("no /dev/bpf device was available")
}

func ifReq(fd *os.File, ifName string) error {
	req := struct {
		Name [0x10]byte
		pad  [0x28 - 0x10]byte
	}{}

	copy(req.Name[:], ifName)

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd.Fd(), uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return fmt.Errorf("unable to IOCTL: %w", errno)
	}

	return nil
}

func ioCtl(fd *os.File) (int, error) {
	var bufLen int

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd.Fd(), uintptr(unix.BIOCIMMEDIATE), uintptr(unsafe.Pointer(&bufLen)))
	if errno != 0 {
		return 0, errno
	}
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd.Fd(), uintptr(unix.BIOCGBLEN), uintptr(unsafe.Pointer(&bufLen)))
	if errno != 0 {
		return 0, errno
	}

	return bufLen, nil
}

// NewDev returns a handle to BPF device. ifName is the interface name to be
// listened on, and frameFilter is used to determine whether a frame should be
// discarded when reading. Set it to nil to disable filtering.
// TODO: use kernel for filtering
func newDev(ifce *net.Interface) (bpfDev, error) {
	var d bpfDev

	fd, dev, err := getBpfFd()
	if err != nil {
		return d, fmt.Errorf("unable to find bpf dev: %w", err)
	}

	if err := ifReq(fd, ifce.Name); err != nil {
		return d, fmt.Errorf("unable to ifReq(%s): %w", dev, err)
	}

	bufLen, err := ioCtl(fd)
	if err != nil {
		return d, fmt.Errorf("unable to ioCtl: %w", err)
	}

	d.fd = fd
	d.ifce = ifce
	d.dev = dev
	d.readBuf = make([]byte, bufLen)

	return d, nil
}

func (b *bpfDev) Close() {
	b.fd.Close()
}

type bpfDev struct {
	ifce *net.Interface
	fd   *os.File
	dev  string

	// bpf may return more than one frame per read() call
	readBuf []byte
}
