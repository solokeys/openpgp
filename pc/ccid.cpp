
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
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
    0x072f,                 // Vendor ID  (1209)
    0x90cc,                 // Product ID (5070)
    0x0100,                 // Device release number in BCD format
    0x01,                   // Manufacturer string index
    0x03,                   // Product string index
    0x04,                   // Device serial number string index
    0x01                    // Number of possible configurations
};

const USB_DEVICE_QUALIFIER_DESCRIPTOR dev_qua = { // A high-speed capable device that has different device information for full-speed and high-speed must have a Device Qualifier Descriptor 
    0x0A,                   // bLength
    0x06,                   // bDescriptorType
    0x0200,                 // bcdUSB 
    0x00,                   // bDeviceClass
    0x00,                   // bDeviceSubClass
    0x00,                   // bDeviceProtocol
    CCID_DATA_PACKET_SIZE,  // bMaxPacketSize
    0x01,                   // bNumConfigurations
    0x00                    // RFU == 0
};


/* Configuration 1 Descriptor */
const CONFIG_CCID  configuration_ccid={{
    /* Configuration Descriptor */
    0x09,//sizeof(USB_CFG_DSC),    // Size of this descriptor in bytes
    USB_DESCRIPTOR_CONFIGURATION,  // CONFIGURATION descriptor type
    sizeof(CONFIG_CCID),           // Total length of data for this cfg
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
    0x0100,                 // bcdCCID: revision 1.1 (of CCID) 
    0x00,                   // bMaxSlotIndex: 0
    0x01,                   // bVoltageSupport: 5V-only
    0x00000002,             // dwProtocols: T=1 
    0x00000fa0,             // dwDefaultClock: 4000 
    0x00000fa0,             // dwMaximumClock: 4000 
    0x00,                   // bNumClockSupported: 0x00 
    0x00002580,             // dwDataRate: 9600 
    0x00002580,             // dwMaxDataRate: 9600 
    0x00,                   // bNumDataRateSupported: 0x00 
    0x000000fe,             // dwMaxIFSD: 254 
    0x00000000,             // dwSynchProtocols: 0 
    0x00000000,             // dwMechanical: 0 
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
    0x0000010f,             // dwMaxCCIDMessageLength: 271 
    0xff,                   // bClassGetResponse: 0xff 
    0x00,                   // bClassEnvelope: 0 
    0x0000,                 // wLCDLayout: 0 
    0x00,                   // bPinSupport: No PIN pad 
    0x01,                   // bMaxCCIDBusySlots: 1 
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

const unsigned char string_1[] = { // Manufacturer
		0x10, 
        USB_DESCRIPTOR_STRING, // bLength, bDscType
		'S', 0x00, 
		'o', 0x00, 
		'l', 0x00, 
		'o', 0x00, 
		'D', 0x00, 
		'e', 0x00, 
		'v', 0x00, 
		};

const unsigned char string_2[] = { 
		0x11, 
        USB_DESCRIPTOR_STRING, 
		'U', 0x00, 
		'S', 0x00, 
		'B', 0x00, 
		' ', 0x00, 
		'C', 0x00, 
		'C', 0x00, 
		'I', 0x00, 
		'D', 0x00, 
		};

const unsigned char string_3[] = { // product
		0x18, 
        USB_DESCRIPTOR_STRING, 
		'V', 0x00, 
		'i', 0x00, 
		'r', 0x00, 
		't', 0x00, 
		'u', 0x00, 
		'a', 0x00, 
		'l', 0x00, 
		' ', 0x00, 
        'U', 0x00, 
        'S', 0x00, 
        'B', 0x00, 
		};
        
const unsigned char string_4[] = { // serial number
		0x18, 
        USB_DESCRIPTOR_STRING, 
		'1', 0x00, 
		'2', 0x00, 
		'3', 0x00, 
		'4', 0x00, 
		'5', 0x00, 
		'6', 0x00, 
		'7', 0x00, 
		'8', 0x00, 
        '9', 0x00, 
        'A', 0x00, 
        'B', 0x00, 
		};


const char *configuration = (const char *)&configuration_ccid; 

const USB_INTERFACE_DESCRIPTOR *interfaces[] = {&configuration_ccid.dev_int0};

const unsigned char *strings[] = {string_0, string_1, string_2, string_3, string_4};


#define BSIZE 2048 
static uint8_t buffer[BSIZE + 1];
static size_t  bsize = 0;

static uint8_t bufferout[BSIZE + 1];
static size_t  bsizeout = 0;

bool ICCStateChanged = true;

bool ProcessCCIDTransfer(uint8_t *datain, size_t datainlen, uint8_t *dataout, size_t *dataoutlen);

void handle_data(int sockfd, USBIP_RET_SUBMIT *usb_req, int bl) {  
    // data channel
    if(usb_req->ep == 0x04)
    {  
        printf("##Data (EP4) received \n"); 
        
        if(usb_req->direction == 0) //input
        { 
            printf("direction=input\n");  
            bsize=recv (sockfd, (char *)buffer, bl, 0);
                        
            bool res = ProcessCCIDTransfer(buffer, bsize, bufferout, &bsizeout);
            // ACK
            send_usb_req(sockfd, usb_req, nullptr, 0, res ? 0 : 1);
        }
        else
        {    
            printf("direction=output\n");  
            send_usb_req(sockfd, usb_req, (char *)bufferout, bsizeout, 0); 
            bsizeout = 0;
       }
     }
  
    // Interrupt channel
    if((usb_req->ep == 0x05)) {
        printf("##Interrupt (EP5) received \n"); 
        if(usb_req->direction == 0) { 
            printf("direction=input. WARNNING!!!!\n");  
            //not supported
            send_usb_req(sockfd, usb_req, nullptr, 0, 0);
            //usleep(500);
        } else {
            printf("direction=output\n");  

            // b0 - slot0 current state b1 - slot0 changed state
            uint8_t state = ICC_PRESENT | (ICCStateChanged ? ICC_CHANGE : 0x00);
            uint8_t data[] = {RDR_TO_PC_NOTIFYSLOTCHANGE, state}; 
            ICCStateChanged = false;
            send_usb_req(sockfd, usb_req, (char*)data, 2, 0);
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
            send_usb_req(sockfd,usb_req,nullptr,0,0);
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
            send_usb_req(sockfd,usb_req,nullptr,0,0);
          }
          if(control_req->bRequest == 0x23)  //SEND_BREAK
          {
            printf("SEND_BREAK\n");   
            send_usb_req(sockfd,usb_req,nullptr,0,0);
          }
        } 

};

int main()
{
   printf("ccid started....\n");
   usbip_run(&dev_dsc);
   printf("ccid stopped....\n");
}

#define ABDATA_SIZE 261

typedef struct { 
    uint8_t bMessageType; /* Offset = 0*/
    uint32_t dwLength;    /* Offset = 1, The length field (dwLength) is the length  
                            of the message not including the 10-byte header.*/
    uint8_t bSlot;        /* Offset = 5*/
    uint8_t bSeq;         /* Offset = 6*/
    uint8_t bSpecific_0;  /* Offset = 7*/
    uint8_t bSpecific_1;  /* Offset = 8*/
    uint8_t bSpecific_2;  /* Offset = 9*/
    uint8_t abData [ABDATA_SIZE]; /* Offset = 10, For reference, the absolute 
                            maximum block size for a TPDU T=0 block is 260 bytes 
                            (5 bytes command; 255 bytes data), 
                            or for a TPDU T=1 block is 259 bytes, 
                            or for a short APDU T=1 block is 261 bytes, 
                            or for an extended APDU T=1 block is 65544 bytes.*/
} __attribute__((packed, aligned(1))) CCID_bulkin_data_t; 

typedef struct { 
    uint8_t bMessageType;   /* Offset = 0*/
    uint32_t dwLength;      /* Offset = 1*/
    uint8_t bSlot;          /* Offset = 5, Same as Bulk-OUT message */
    uint8_t bSeq;           /* Offset = 6, Same as Bulk-OUT message */
    uint8_t bStatus;        /* Offset = 7, Slot status as defined in § 6.2.6*/
    uint8_t bError;         /* Offset = 8, Slot error  as defined in § 6.2.6*/
    uint8_t bSpecific;      /* Offset = 9*/
    uint8_t abData[ABDATA_SIZE]; /* Offset = 10*/
    uint16_t u16SizeToSend; 
} __attribute__((packed, aligned(1))) CCID_bulkout_data_t;

static const uint8_t atrconst[] = {
    0x3B, 0xDA, 0x11, 0xFF, 0x81, 0xB1, 0xFE, 0x55, 
    0x1F, 0x03, 0x00, 0x31, 0x84, 0x73, 0x80, 0x01, 
    0x80, 0x00, 0x90, 0x00, 0xE4 };

void CCID_UpdateResponseStatus(CCID_bulkout_data_t *pckout, uint8_t status, uint8_t error) {
    pckout->bStatus = status;
    pckout->bError = error;
};

void PC_to_RDR_IccPowerOn(CCID_bulkin_data_t *pckin, CCID_bulkout_data_t *pckout) {
    uint8_t voltage = pckin->bSpecific_0;
    if (voltage >= VOLTS_1_8) {
        /* The Voltage specified is out of Spec */
        CCID_UpdateResponseStatus(pckout, BM_COMMAND_STATUS_FAILED | BM_ICC_PRESENT_ACTIVE, SLOTERROR_BAD_POWERSELECT);
        return; 
    }
    
    pckout->dwLength = sizeof(atrconst);
    memmove(pckout->abData, atrconst, sizeof(atrconst));

    CCID_UpdateResponseStatus(pckout, BM_COMMAND_STATUS_NO_ERROR | BM_ICC_PRESENT_ACTIVE, SLOT_NO_ERROR);
};

void PC_to_RDR_IccPowerOff(CCID_bulkin_data_t *pckin, CCID_bulkout_data_t *pckout) {
    
    CCID_UpdateResponseStatus(pckout, BM_COMMAND_STATUS_NO_ERROR | BM_ICC_PRESENT_ACTIVE, SLOT_NO_ERROR);
};

void PC_to_RDR_GetSlotStatus(CCID_bulkin_data_t *pckin, CCID_bulkout_data_t *pckout) {
    
    CCID_UpdateResponseStatus(pckout, BM_COMMAND_STATUS_NO_ERROR | BM_ICC_PRESENT_ACTIVE, SLOT_NO_ERROR);
};

void PC_to_RDR_XfrBlock(CCID_bulkin_data_t *pckin, CCID_bulkout_data_t *pckout) {
    
    pckout->dwLength = 2;
    pckout->abData[0] = 0x90;
    pckout->abData[1] = 0x00;
    
    CCID_UpdateResponseStatus(pckout, BM_COMMAND_STATUS_NO_ERROR | BM_ICC_PRESENT_ACTIVE, SLOT_NO_ERROR);
};

void RDR_to_PC_NotifySlotChange(void) {
};

void RDR_to_PC_SlotStatus(CCID_bulkout_data_t *pckout) {
    pckout->bMessageType = RDR_TO_PC_SLOTSTATUS; 
    pckout->dwLength  = 0;
    pckout->bSpecific = 0;    /* bClockStatus = 00h Clock running
                                                01h Clock stopped in state L
                                                02h Clock stopped in state H
                                                03h Clock stopped in an unknown state
                                                All other values are RFU. */                                                                            
};

void RDR_to_PC_DataBlock(CCID_bulkout_data_t *pckout) {
    pckout->bMessageType = RDR_TO_PC_DATABLOCK; 
    pckout->bSpecific = 0;    /* bChainParameter */
    
    // if error - no data send
    if(pckout->bError != SLOT_NO_ERROR) {
        pckout->dwLength = 0;  
    }     
};

bool ProcessCCIDTransfer(uint8_t *datain, size_t datainlen, uint8_t *dataout, size_t *dataoutlen) {

    *dataoutlen = 0;
    
    if (datainlen < 10)
        return false;
    
    printf("<<<[%ld]: ", datainlen);
    for (size_t i = 0; i < datainlen; i++)
        printf("%02x ",datain[i]);
    printf("\n"); 
    
    CCID_bulkin_data_t *sdatain = (CCID_bulkin_data_t *)datain;
    
    if (sdatain->dwLength + CCID_HEADER_SIZE != datainlen)
        return false;
    
    // structures vice versa!    
    CCID_bulkout_data_t  *sdataout = (CCID_bulkout_data_t *)dataout;
    memset(dataout, 0x00, CCID_HEADER_SIZE);
    sdataout->bSlot = sdatain->bSlot;
    sdataout->bSeq = sdatain->bSeq;
    
    switch (sdatain->bMessageType) {
    case PC_TO_RDR_ICCPOWERON:
        PC_to_RDR_IccPowerOn(sdatain, sdataout);
        RDR_to_PC_DataBlock(sdataout);
        break;
    case PC_TO_RDR_ICCPOWEROFF:
        PC_to_RDR_IccPowerOff(sdatain, sdataout);
        RDR_to_PC_SlotStatus(sdataout);
        break;
    case PC_TO_RDR_GETSLOTSTATUS:
        PC_to_RDR_GetSlotStatus(sdatain, sdataout);
        RDR_to_PC_SlotStatus(sdataout);
        break;
    case PC_TO_RDR_XFRBLOCK:
        PC_to_RDR_XfrBlock(sdatain, sdataout);
        RDR_to_PC_DataBlock(sdataout);
        break;
/*
    case PC_TO_RDR_GETPARAMETERS:
        errorCode = PC_to_RDR_GetParameters();
        RDR_to_PC_Parameters(errorCode);
        break;
    case PC_TO_RDR_RESETPARAMETERS:
        errorCode = PC_to_RDR_ResetParameters();
        RDR_to_PC_Parameters(errorCode);
        break;
    case PC_TO_RDR_SETPARAMETERS:
        errorCode = PC_to_RDR_SetParameters();
        RDR_to_PC_Parameters(errorCode);
        break;
    case PC_TO_RDR_ESCAPE:
        errorCode = PC_to_RDR_Escape();
        RDR_to_PC_Escape(errorCode);
        break;
    case PC_TO_RDR_ICCCLOCK:
        errorCode = PC_to_RDR_IccClock();
        RDR_to_PC_SlotStatus(errorCode);
        break;
    case PC_TO_RDR_ABORT:
        errorCode = PC_to_RDR_Abort();
        RDR_to_PC_SlotStatus(errorCode);
        break;
    case PC_TO_RDR_T0APDU:
        errorCode = PC_TO_RDR_T0Apdu();
        RDR_to_PC_SlotStatus(errorCode);
        break;
    case PC_TO_RDR_MECHANICAL:
        errorCode = PC_TO_RDR_Mechanical();
        RDR_to_PC_SlotStatus(errorCode);
        break;   
    case PC_TO_RDR_SETDATARATEANDCLOCKFREQUENCY:
        errorCode = PC_TO_RDR_SetDataRateAndClockFrequency();
        RDR_to_PC_DataRateAndClockFrequency(errorCode);
        break;
    case PC_TO_RDR_SECURE:
        errorCode = PC_TO_RDR_Secure();
        RDR_to_PC_DataBlock(errorCode);
        break;
        */
    default:
        CCID_UpdateResponseStatus(sdataout, BM_COMMAND_STATUS_FAILED | BM_ICC_PRESENT_ACTIVE, SLOTERROR_CMD_NOT_SUPPORTED);
        RDR_to_PC_SlotStatus(sdataout);
        break;
    };    
    
    *dataoutlen = CCID_HEADER_SIZE + sdataout->dwLength;
    
    printf(">>>[%ld]: ", *dataoutlen);
    for (size_t i = 0; i < *dataoutlen; i++)
        printf("%02x ",dataout[i]);
    printf("\n"); 
    
    return true;
}

