
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "usbip.h"

/* Device Descriptor */
const USB_DEVICE_DESCRIPTOR dev_dsc=
{
    0x12,                   // Size of this descriptor in bytes
    0x01,                   // DEVICE descriptor type
    0x0200,                 // USB Spec Release Number in BCD format
    0x00,                   // Class Code
    0x00,                   // Subclass code
    0x00,                   // Protocol code
    0x10,                   // Max packet size for EP0, see usb_config.h
    0x03EB,                 // Vendor ID
    0x206E,                 // Product ID
    0x0100,                 // Device release number in BCD format
    0x01,                   // Manufacturer string index
    0x03,                   // Product string index
    0x00,                   // Device serial number string index
    0x01                    // Number of possible configurations
};

const USB_DEVICE_QUALIFIER_DESCRIPTOR dev_qua = { // ????
    0x0A,       // bLength
    0x06,       // bDescriptorType
    0x0200,     // bcdUSB 
    0x02,       // bDeviceClass
    0x00,       // bDeviceSubClass
    0x00,       // bDeviceProtocol
    0x10,       // bMaxPacketSize
    0x01,       // iSerialNumber
    0x00        // bNumConfigurations
};


/* Configuration 1 Descriptor */
const CONFIG_CCID  configuration_ccid={{
    /* Configuration Descriptor */
    0x09,//sizeof(USB_CFG_DSC),    // Size of this descriptor in bytes
    USB_DESCRIPTOR_CONFIGURATION,  // CONFIGURATION descriptor type
    sizeof(CONFIG_CDC),            // Total length of data for this cfg
    1,                             // Number of interfaces in this cfg
    1,                             // Index value of this configuration
    0,                             // Configuration string index
    0xC0,                          // b8 = 1 mandatory, b7=1 self powered
    50,                            // Max power consumption (2X mA). 50 = 100mA
    },{ 
    /* Interface Descriptor */
    0x09,//sizeof(USB_INTF_DSC),   // Size of this descriptor in bytes
    USB_DESCRIPTOR_INTERFACE,               // INTERFACE descriptor type
    0,                      // Interface Number
    0,                      // Alternate Setting Number
    3,                      // Number of endpoints in this intf
    0x0b,                   // Class code (CCID class)
    0x00,                   // Subclass code
    0x00,                   // Protocol code
    0                       // Interface string index
    },{
    /* ICC Descriptor */
    54,                     // bLength: 
    USB_DESCRIPTOR_ICC,     // bDescriptorType: USBDESCR_ICC 
    0x0110,                 // bcdCCID: revision 1.1 (of CCID) 
    0x00,                   /* bMaxSlotIndex: */
    0x01,                   /* bVoltageSupport: 5V-only */
    0x00000002,             /* dwProtocols: T=1 */
    0x00000fa0,             /* dwDefaultClock: 4000 */
    0x00000fa0,             /* dwMaximumClock: 4000 */
    0x00,                   /* bNumClockSupported: 0x00 */
    0x00002580,             /* dwDataRate: 9600 */
    0x00002580,             /* dwMaxDataRate: 9600 */
    0x00,                   /* bNumDataRateSupported: 0x00 */
    0x000000fe,             /* dwMaxIFSD: 254 */
    0x00000000,             /* dwSynchProtocols: 0 */
    0x00000000,             /* dwMechanical: 0 */
    0x0002047a,             /* dwFeatures:
                                *  Short and extended APDU level: 0x40000 ----
                                *  Short APDU level             : 0x20000  *
                                *  (ICCD?)                      : 0x00800 ----
                                *  Automatic IFSD               : 0x00400   *
                                *  NAD value other than 0x00    : 0x00200
                                *  Can set ICC in clock stop    : 0x00100
                                *  Automatic PPS CUR            : 0x00080
                                *  Automatic PPS PROP           : 0x00040 *
                                *  Auto baud rate change	    : 0x00020   *
                                *  Auto clock change		    : 0x00010   *
                                *  Auto voltage selection	    : 0x00008   *
                                *  Auto activaction of ICC	    : 0x00004
                                *  Automatic conf. based on ATR : 0x00002  *
                                */
    0x0000010f,             /* dwMaxCCIDMessageLength: 271 */
    0xff,                   /* bClassGetResponse: 0xff */
    0x00,                   /* bClassEnvelope: 0 */
    0x0000,                 /* wLCDLayout: 0 */
    0x00,                   /* bPinSupport: No PIN pad */
    0x01,                   /* bMaxCCIDBusySlots: 1 */
    },{ 
    /* Endpoint Descriptors */
    /* Endpoint IN1 Descriptor */
    sizeof(USB_ENDPOINT_DESCRIPTOR),
    USB_DESCRIPTOR_ENDPOINT,    //Endpoint Descriptor
    CCID_IN_EP,                 //EndpointAddress
    0x02,                       //bmAttributes: Bulk
    CCID_DATA_PACKET_SIZE,      //size // was 34U!!!
    0x00                        //Interval
    },{
    /* Endpoint OUT1 Descriptor */
    0x07,/*sizeof(USB_EP_DSC)*/
    USB_DESCRIPTOR_ENDPOINT,    //Endpoint Descriptor
    CCID_OUT_EP,                //EndpointAddress
    0x02,                       //bmAttributes: Bulk
    CCID_DATA_PACKET_SIZE,      //size
    0x00                        //Interval
    },{
    /* Endpoint IN2 Descriptor */
    0x07,/*sizeof(USB_EP_DSC)*/
    USB_DESCRIPTOR_ENDPOINT,    //Endpoint Descriptor
    CCID_CMD_EP,                //EndpointAddress
    0x03,                       //bmAttributes: Interrupt
    0x0004,                     //wMaxPacketSize: 4
    0xff                        //Interval 255ms
    }
};


const unsigned char string_0[] = { // available languages  descriptor
		0x04,
        USB_DESCRIPTOR_STRING, 
		0x09,                      //  0x0409 (English - United States)
        0x04 
		};

const unsigned char string_1[] = { //
		0x0A, 
        USB_DESCRIPTOR_STRING, // bLength, bDscType
		'T', 0x00, //
		'e', 0x00, //
		's', 0x00, //
		't', 0x00, //
		};

const unsigned char string_2[] = { //
		0x11, 
        USB_DESCRIPTOR_STRING, //
		'U', 0x00, //
		'S', 0x00, //
		'B', 0x00, //
		' ', 0x00, //
		'C', 0x00, //
		'C', 0x00, //
		'I', 0x00, //
		'D', 0x00, //
		};

const unsigned char string_3[] = { //
		0x18, 
        USB_DESCRIPTOR_STRING, //
		'V', 0x00, //
		'i', 0x00, //
		'r', 0x00, //
		't', 0x00, //
		'u', 0x00, //
		'a', 0x00, //
		'l', 0x00, //
		' ', 0x00, //
        'U', 0x00, //
        'S', 0x00, //
        'B', 0x00, //
		};


const char *configuration = (const char *)&configuration_ccid; 

const USB_INTERFACE_DESCRIPTOR *interfaces[] = {&configuration_ccid.dev_int0};

const unsigned char *strings[] = {string_0, string_1, string_2, string_3};


#define BSIZE 64 
char buffer[BSIZE+1];
int  bsize=0;


void handle_data(int sockfd, USBIP_RET_SUBMIT *usb_req, int bl)
{   
    
  if(usb_req->ep == 0x01)
  {  
    printf("EP1 received \n"); 
    
    if(usb_req->direction == 0) //input
    { 
      printf("direction=input\n");  
      bsize=recv (sockfd, (char *) buffer , bl, 0);
      send_usb_req(sockfd, usb_req,"", 0, 0);
      buffer[bsize+1]=0; //string terminator
      printf("received (%s)\n",buffer);
    }
    else
    {    
        printf("direction=output\n");  
    }
    //not supported
    send_usb_req(sockfd, usb_req, "", 0, 0);
    usleep(500);
  }
  
  if((usb_req->ep == 0x02))
  {
    printf("EP2 received \n"); 
    if(usb_req->direction == 0) //input
    { 
      int i;
      printf("direction=input\n");  
      bsize=recv (sockfd, (char *) buffer , bl, 0);
      send_usb_req(sockfd, usb_req,"", 0, 0);
      buffer[bsize+1]=0; //string terminator
      printf("received (%s)\n",buffer);
      for(i=0;i<bsize;i++)
          printf("%02X",(unsigned char)buffer[i]);
      printf("\n");       
    }
    else //output
    {
      printf("direction=output\n");  
      if(bsize != 0)
      {   
        int i;
        for(i=0;i<bsize;i++)//increment received char
           buffer[i]+=1;

        send_usb_req(sockfd, usb_req, buffer, bsize, 0);    
        printf("sending (%s)\n",buffer);
        bsize=0;
      }
      else
      {
        send_usb_req(sockfd, usb_req,"", 0, 0);    
        usleep(500);
        printf("no data disponible\n");
      }
    }
  }
  
};


typedef struct _LINE_CODING
{
    word dwDTERate;  //in bits per second
    byte bCharFormat;//0-1 stop; 1-1.5 stop; 2-2 stop bits
    byte ParityType; //0 none; 1- odd; 2 -even; 3-mark; 4 -space
    byte bDataBits;  //5,6,7,8 or 16
}LINE_CODING;



LINE_CODING linec;

unsigned short linecs=0;

void handle_unknown_control(int sockfd, StandardDeviceRequest * control_req, USBIP_RET_SUBMIT *usb_req)
{
        if(control_req->bmRequestType == 0x21)//Abstract Control Model Requests
        { 
          if(control_req->bRequest == 0x20)  //SET_LINE_CODING
          {
            printf("SET_LINE_CODING\n");   
            if ((recv (sockfd, (char *) &linec , control_req->wLength, 0)) != control_req->wLength)
            {
              printf ("receive error : %s \n", strerror (errno));
              exit(-1);
            };
            send_usb_req(sockfd,usb_req,"",0,0);
          } 
          if(control_req->bRequest == 0x21)  //GET_LINE_CODING
          {
            printf("GET_LINE_CODING\n");  
            send_usb_req(sockfd,usb_req,(char *)&linec,7,0);
          }
          if(control_req->bRequest == 0x22)  //SET_LINE_CONTROL_STATE
          {
            linecs=control_req->wValue0;
            printf("SET_LINE_CONTROL_STATE 0x%02X\n", linecs);   
            send_usb_req(sockfd,usb_req,"",0,0);
          }
          if(control_req->bRequest == 0x23)  //SEND_BREAK
          {
            printf("SEND_BREAK\n");   
            send_usb_req(sockfd,usb_req,"",0,0);
          }
        } 

};

int main()
{
   printf("ccid started....\n");
   usbip_run(&dev_dsc);
   printf("ccid stopped....\n");
}

