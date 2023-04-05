/* 
Author: Aravind Prabhakar
Version: v1.0
Description: This is an Inline monitoring ipfix collector. 
	     Just decodes ipfix packet and prints it on display.
	     Additionally decodes the data_stream field as 
	     well in case there is any present. Typically inline monitoring 
	     data when sent from jnpr routers will encapsulate packet with 
	     ipfix header. This is used to decode the same.

*/

package main

import (
	"fmt"
	//"net"
	"encoding/hex"
	 "github.com/google/gopacket"
	 "github.com/google/gopacket/layers"
	 "github.com/google/gopacket/pcap"
	 "github.com/akamensky/argparse"
	 "os"
	 //"strings"
	 "strconv"
	 "time"
	 "log"
)

//packet handling variables
var (
    snapshotLen int32  = 1024
    promiscuous bool   = false
    err         error
    timeout     time.Duration = 5 * time.Second
    handle      *pcap.Handle
)

// Decode bytes and return a dotted val of IP address
func Ipv4Decode(input []byte) string {
    var val [4]string
    for i:=0;i<len(input);i++ {
        hexval := hex.EncodeToString(input[i:i+1])
        dval,_ := strconv.ParseInt(hexval, 16, 64)
        val[i] = strconv.FormatInt(dval,10)
    }
    return val[0]+"."+val[1]+"."+val[2]+"."+val[3]
}

// Decode port bytes and return an int64 value
func PortDecode(input []byte) int64 {
    hexval := hex.EncodeToString(input)
    dval,_ := strconv.ParseInt(hexval, 16, 64)
    return dval
}

/*func MacDecode(input []byte) string {
	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()
}*/

// Inline monitoring Ipfix template data 
type IpfixTempData struct {
    Timestamp string
    ObservationId string
    Version string
    FlowsetId string
    Flowlen string
    Length string
    TemplateId string
    Flowseq string
}

// IPFIX Flow data definition
type IpfixGtpFlowData struct {
	OuterSrcIp string
	OuterDstIp string
	OuterSrcPort int64
	OuterDstPort int64
	GtpTeid string
   	GtpIpSrcAddr string
    	GtpIpDstAddr string
    	GtpProtocol int64
    	GtpL4SrcPort int64
    	GtpL4DstPort int64
}

type IpfixData struct {
	EgressIntf string
	IngressIntf string
	Direction string
	DataLinkSize string
}

var template IpfixTempData

// Decode GTP-U packet
func decodeGtp(payload []byte) {
	fmt.Println("decoding GTP packet.. \n")
	//var iflow IpfixGtpFlowData
	gtpPacket := gopacket.NewPacket(payload,layers.LayerTypeEthernet,gopacket.Default)
    	ethLayer := gtpPacket.Layer(layers.LayerTypeEthernet)
    	if ethLayer != nil {
    	    	gtpPacket,_ := ethLayer.(*layers.Ethernet)
    	    	fmt.Println("Original pkt Outer Source Mac: ", gtpPacket.SrcMAC)
    	    	fmt.Println("Original pkt Dest Mac: ", gtpPacket.DstMAC)
    	    	fmt.Println("Original pkt Eth Type: ", gtpPacket.EthernetType)
    	}

    	// Outer Iplayer
    	ipLayer := gtpPacket.Layer(layers.LayerTypeIPv4)
    	if ipLayer != nil {
    	    	ipPacket,_ := ipLayer.(*layers.IPv4)
    	    	fmt.Println("Original pkt Source IP: ", ipPacket.SrcIP)
    	    	fmt.Println("Original pkt Dest IP: ", ipPacket.DstIP)
    	    	fmt.Println("Original pkt Protocol: ", ipPacket.Protocol)
	}

	udpLayer := gtpPacket.Layer(layers.LayerTypeUDP)
    	//var originalUdpPort layers.UDPPort
    	if udpLayer != nil {
        	udp,_ := udpLayer.(*layers.UDP)
        	fmt.Println("Original pkt Source Port: ", udp.SrcPort)
        	fmt.Println("Original pkt Dest Port: ", udp.DstPort)
    	}

	gtpLayer := gtpPacket.Layer(layers.LayerTypeGTPv1U)
	if gtpLayer != nil {
		fmt.Println("============ GTP Layer ============= \n")
		gtp,_ := gtpLayer.(*layers.GTPv1U)
		fmt.Println("TEID: ", gtp.TEID)
	}

	/*iflow.OuterDstMac = 
	iflow.OuterSrcMac = 
	iflow.GtpTeid = PortDecode(payload[6:12]) 
	iflow.GtpIpSrcAddr = Ipv4Decode(payload[]) 
	iflow.GtpIpDstAddr = Ipv4Decode(payload[])
	iflow.GtpProtocol = PortDecode(payload[])
	iflow.GtpL4SrcPort = PortDecode(payload[])
	iflow.GtpL4DstPort = PortDecode(payload[])*/
}

// Decode IPfix packet
func decodeIpfix(payload []byte) {
	var iflow IpfixData
	iFixVersion := payload[0:2]
	if hex.EncodeToString(iFixVersion) == "000a" {
		fmt.Println("Decoding IPFIX packet...")
		iFixFlowSetId := hex.EncodeToString(payload[16:18])
		//fmt.Println(iFixFlowSetId)
		if iFixFlowSetId == "0002" {
			fmt.Println(" received template packet ....\n")
			template.Version = hex.EncodeToString(iFixVersion)
			template.Length = hex.EncodeToString(payload[2:4])
			template.Timestamp = hex.EncodeToString(payload[4:8])
			template.Flowseq = hex.EncodeToString(payload[8:12])
			template.ObservationId = hex.EncodeToString(payload[12:16])
			template.FlowsetId = hex.EncodeToString(payload[16:18])
			template.Flowlen = hex.EncodeToString(payload[18:20])
			template.TemplateId = hex.EncodeToString(payload[20:22])
			//fmt.Println(template)
		} else if iFixFlowSetId == template.TemplateId {
			fmt.Println("Decoding inline monitoring flow packet... \n")
			//TO_DO: Add check for Inner IP version before decoding to handle v4 vs v6 versions
			iflow.EgressIntf = hex.EncodeToString(payload[20:24])
			iflow.IngressIntf = hex.EncodeToString(payload[24:28])
			iflow.Direction = hex.EncodeToString(payload[28:29])
			iflow.DataLinkSize = hex.EncodeToString(payload[29:31])
			fmt.Println("EgressIntf: ", iflow.EgressIntf)
			fmt.Println("IngressIntf: ", iflow.IngressIntf)
			fmt.Println("Direction: ", iflow.Direction)
			fmt.Println("DataLinkSize: ", iflow.DataLinkSize)
			if iflow.DataLinkSize != "" {
				//Inner Packet to parse 
				decodeGtp(payload[32:])
			}
		} else {
			fmt.Println("Unable to decode Ipfix Packet... \n")
		}
	} else {
		fmt.Println("Not an IPFIX packet ... \n")
	}
}


func decodePacket(packet gopacket.Packet) {
    // Flow information to store
    // Outer Ethernet layer
    //Outer UdpLayer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
    	var uDestPort layers.UDPPort
    	if udpLayer != nil {
        	udp,_ := udpLayer.(*layers.UDP)
        	//fmt.Println("Source Port: ", udp.SrcPort)
        	//fmt.Println("Dest Port: ", udp.DstPort)
        	//fmt.Println("UDP Length: ", udp.Length)
        	uDestPort = udp.DstPort
    	}
    	if uDestPort == 1000 {
        	fmt.Println("received ipfix packet...")
        	//IPfix Layer (payload) decoding
        	//payload decoded as applicationLayer
        	appLayer := packet.ApplicationLayer()
        	if appLayer != nil {
            		payload := appLayer.Payload()
			decodeIpfix(payload)
        	}	
	}
}

func main() {
	logs, logerr := os.OpenFile("imon-decoder.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if logerr != nil {
		log.Fatalf("Error opening file: %v", logerr)
	}
	defer logs.Close()
	log.SetOutput(logs)
	parser := argparse.NewParser("Required-args", "\n============\nimon-ipfix-decoder\n============")
	device := parser.String("i", "intf", &argparse.Options{Required: true, Help: "interface to bind to "})
	//cport := parser.String("p", "port", &argparse.Options{Required: true, Help: "port number over which ipfix packets arrive "})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	} else {
		handle, err = pcap.OpenLive(*device, snapshotLen, promiscuous, timeout)
		if err != nil { log.Fatal(err) }
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			go decodePacket(packet)
		}
	}
}
