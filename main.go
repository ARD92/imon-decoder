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
	"net"
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
    template	IpfixTempData
)

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
	GtpTeid uint32
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
	DataLinkSize int64
}

type Ipv4Flow struct {
	Srcmac net.HardwareAddr
	Dstmac net.HardwareAddr
	SrcIp net.IP
	DstIp net.IP
	SrcPort layers.UDPPort
	DstPort layers.UDPPort
	Protocol layers.IPProtocol

}

// Parse IPv4 bytes and return string value in dotted decimal
func parseIpv4Bytes(input []byte) string {
    	var val [4]string
    	for i:=0;i<len(input);i++ {
    	    hexval := hex.EncodeToString(input[i:i+1])
    	    dval,_ := strconv.ParseInt(hexval, 16, 64)
    	    val[i] = strconv.FormatInt(dval,10)
    	}
    	return val[0]+"."+val[1]+"."+val[2]+"."+val[3]
}

// Decode port bytes and return an int64 value
func parsePortBytes(input []byte) int64 {
    	hexval := hex.EncodeToString(input)
    	dval,_ := strconv.ParseInt(hexval, 16, 64)
    	return dval
}


func decodeIpv4(payload []byte) (gopacket.Packet, Ipv4Flow) {
	var v4flow Ipv4Flow
	packet := gopacket.NewPacket(payload,layers.LayerTypeEthernet,gopacket.Default)
    	ethLayer := packet.Layer(layers.LayerTypeEthernet)
    	if ethLayer != nil {
    	    	eth,_ := ethLayer.(*layers.Ethernet)
		v4flow.Srcmac = eth.SrcMAC
		v4flow.Dstmac = eth.DstMAC
    	}

    	ipLayer := packet.Layer(layers.LayerTypeIPv4)
    	if ipLayer != nil {
    	    	ipacket,_ := ipLayer.(*layers.IPv4)
		v4flow.SrcIp = ipacket.SrcIP
		v4flow.DstIp = ipacket.DstIP
		v4flow.Protocol = ipacket.Protocol
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
    	if udpLayer != nil {
        	udp,_ := udpLayer.(*layers.UDP)
		v4flow.SrcPort = udp.SrcPort
		v4flow.DstPort = udp.DstPort
    	}
	return packet, v4flow
}

// Decode GTP-U packet
func decodeGtp(payload []byte) {
	var gtpFlow IpfixGtpFlowData
	packet, _ := decodeIpv4(payload)
	gtpLayer := packet.Layer(layers.LayerTypeGTPv1U)
	if gtpLayer != nil {
		fmt.Println("============ GTP Layer ============= \n")
		gtp,_ := gtpLayer.(*layers.GTPv1U)
		fmt.Println("TEID: ", gtp.TEID)
		gtpFlow.GtpTeid = gtp.TEID
    		nextLayer := gtp.NextLayerType()
		if nextLayer == layers.LayerTypeIPv4 {
			gpayload := gtp.LayerPayload()
			gtpFlow.GtpIpSrcAddr = parseIpv4Bytes(gpayload[12:16])
			gtpFlow.GtpIpDstAddr = parseIpv4Bytes(gpayload[16:20])
			gtpFlow.GtpProtocol = parsePortBytes(gpayload[9:10])
			gtpFlow.GtpL4SrcPort = parsePortBytes(gpayload[20:22])
			gtpFlow.GtpL4DstPort = parsePortBytes(gpayload[22:24])
			log.Println("Gtp flow: ", gtpFlow)
			fmt.Println("InnerSourceAddr : ", gtpFlow.GtpIpSrcAddr)
			fmt.Println("InnerDestAddr : ", gtpFlow.GtpIpDstAddr)
			fmt.Println("InnerSourcePort : ", gtpFlow.GtpL4SrcPort)
			fmt.Println("InnerDestPort : ", gtpFlow.GtpL4DstPort)
			fmt.Println("InnerProtocol : ", gtpFlow.GtpProtocol)
			fmt.Println("----------")
		}

	}

}

// Decode IPfix packet
func decodeIpfix(payload []byte) {
	var iflow IpfixData
	iFixVersion := payload[0:2]
	if hex.EncodeToString(iFixVersion) == "000a" {
		log.Println("Decoding IPFIX packet...")
		iFixFlowSetId := hex.EncodeToString(payload[16:18])
		//fmt.Println(iFixFlowSetId)
		if iFixFlowSetId == "0002" {
			log.Println(" received template packet ....\n")
			fmt.Println(" received template packet ....\n")
			template.Version = hex.EncodeToString(iFixVersion)
			template.Length = hex.EncodeToString(payload[2:4])
			template.Timestamp = hex.EncodeToString(payload[4:8])
			template.Flowseq = hex.EncodeToString(payload[8:12])
			template.ObservationId = hex.EncodeToString(payload[12:16])
			template.FlowsetId = hex.EncodeToString(payload[16:18])
			template.Flowlen = hex.EncodeToString(payload[18:20])
			template.TemplateId = hex.EncodeToString(payload[20:22])
			log.Println("template hex bytes: ",template)
		} else if iFixFlowSetId == template.TemplateId {
			log.Println("Decoding inline monitoring flow packet... \n")
			//TO_DO: Add check for Inner IP version before decoding to handle v4 vs v6 versions
			iflow.EgressIntf = hex.EncodeToString(payload[20:24])
			iflow.IngressIntf = hex.EncodeToString(payload[24:28])
			iflow.Direction = hex.EncodeToString(payload[28:29])
			iflow.DataLinkSize = parsePortBytes(payload[29:31])
			log.Println("flow data hexbytes: ",iflow)
			fmt.Println("======== Flow data ============\n")
			fmt.Println("EgressIntf: ", iflow.EgressIntf)
			fmt.Println("IngressIntf: ", iflow.IngressIntf)
			fmt.Println("Direction: ", iflow.Direction)
			fmt.Println("DataLinkSize: ", iflow.DataLinkSize)
			if iflow.DataLinkSize != 0 {
				//Inner Packet to parse 
				decodeGtp(payload[32:])
			}
		} else {
			log.Println("Unable to decode Ipfix Packet... \n")
			fmt.Println("Unable to decode Ipfix Packet... \n")
		}
	} else {
		log.Println("Not an IPFIX packet ... \n")
		fmt.Println("Not an IPFIX packet ... \n")
	}
}


func decodePacket(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
    	var uDestPort layers.UDPPort
    	if udpLayer != nil {
        	udp,_ := udpLayer.(*layers.UDP)
        	uDestPort = udp.DstPort
    	}
    	if uDestPort == 1000 {
        	log.Println("received ipfix packet...")
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
