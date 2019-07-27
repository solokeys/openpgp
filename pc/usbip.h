/* ########################################################################

   USBIP hardware emulation 

   ########################################################################

   Copyright (c) : 2016  Luis Claudio Gambôa Lopes
   Copyright (c) : 2019  Oleg Moiseenko

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   For e-mail suggestions :  lcgamboa@yahoo.com
   ######################################################################## */

#ifdef LINUX
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#define        min(a,b)        ((a) < (b) ? (a) : (b))
#else
#include<winsock.h>
#endif
//system headers independent
#include<errno.h>
#include<stdarg.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<stdint.h>
//defines
#define        TCP_SERV_PORT        3240
typedef struct sockaddr sockaddr;


//USB definitions

#define byte uint8_t
#define word uint16_t
#define dword uint32_t

// USB Descriptors

#define USB_DESCRIPTOR_DEVICE           0x01    // Device Descriptor.
#define USB_DESCRIPTOR_CONFIGURATION    0x02    // Configuration Descriptor.
#define USB_DESCRIPTOR_STRING           0x03    // String Descriptor.
#define USB_DESCRIPTOR_INTERFACE        0x04    // Interface Descriptor.
#define USB_DESCRIPTOR_ENDPOINT         0x05    // Endpoint Descriptor.
#define USB_DESCRIPTOR_DEVICE_QUALIFIER 0x06    // Device Qualifier.
#define USB_DESCRIPTOR_ICC              0x21    // ICC descriptor.

typedef struct __attribute__ ((__packed__)) _USB_DEVICE_DESCRIPTOR
{
    byte bLength;               // Length of this descriptor.
    byte bDescriptorType;       // DEVICE descriptor type (USB_DESCRIPTOR_DEVICE).
    word bcdUSB;                // USB Spec Release Number (BCD).
    byte bDeviceClass;          // Class code (assigned by the USB-IF). 0xFF-Vendor specific.
    byte bDeviceSubClass;       // Subclass code (assigned by the USB-IF).
    byte bDeviceProtocol;       // Protocol code (assigned by the USB-IF). 0xFF-Vendor specific.
    byte bMaxPacketSize0;       // Maximum packet size for endpoint 0.
    word idVendor;              // Vendor ID (assigned by the USB-IF).
    word idProduct;             // Product ID (assigned by the manufacturer).
    word bcdDevice;             // Device release number (BCD).
    byte iManufacturer;         // Index of String Descriptor describing the manufacturer.
    byte iProduct;              // Index of String Descriptor describing the product.
    byte iSerialNumber;         // Index of String Descriptor with the device's serial number.
    byte bNumConfigurations;    // Number of possible configurations.
} USB_DEVICE_DESCRIPTOR;


typedef struct __attribute__ ((__packed__)) _USB_CONFIGURATION_DESCRIPTOR
{
    byte bLength;               // Length of this descriptor.
    byte bDescriptorType;       // CONFIGURATION descriptor type (USB_DESCRIPTOR_CONFIGURATION).
    word wTotalLength;          // Total length of all descriptors for this configuration.
    byte bNumInterfaces;        // Number of interfaces in this configuration.
    byte bConfigurationValue;   // Value of this configuration (1 based).
    byte iConfiguration;        // Index of String Descriptor describing the configuration.
    byte bmAttributes;          // Configuration characteristics.
    byte bMaxPower;             // Maximum power consumed by this configuration.
} USB_CONFIGURATION_DESCRIPTOR;


typedef struct __attribute__ ((__packed__)) _USB_INTERFACE_DESCRIPTOR
{
    byte bLength;               // Length of this descriptor.
    byte bDescriptorType;       // INTERFACE descriptor type (USB_DESCRIPTOR_INTERFACE).
    byte bInterfaceNumber;      // Number of this interface (0 based).
    byte bAlternateSetting;     // Value of this alternate interface setting.
    byte bNumEndpoints;         // Number of endpoints in this interface.
    byte bInterfaceClass;       // Class code (assigned by the USB-IF).  0xFF-Vendor specific.
    byte bInterfaceSubClass;    // Subclass code (assigned by the USB-IF).
    byte bInterfaceProtocol;    // Protocol code (assigned by the USB-IF).  0xFF-Vendor specific.
    byte iInterface;            // Index of String Descriptor describing the interface.
} USB_INTERFACE_DESCRIPTOR;


typedef struct __attribute__ ((__packed__)) _USB_ENDPOINT_DESCRIPTOR
{
    byte bLength;               // Length of this descriptor.
    byte bDescriptorType;       // ENDPOINT descriptor type (USB_DESCRIPTOR_ENDPOINT).
    byte bEndpointAddress;      // Endpoint address. Bit 7 indicates direction (0=OUT, 1=IN).
    byte bmAttributes;          // Endpoint transfer type.
    word wMaxPacketSize;        // Maximum packet size.
    byte bInterval;             // Polling interval in frames.
} USB_ENDPOINT_DESCRIPTOR;

typedef struct __attribute__ ((__packed__)) _USB_DEVICE_QUALIFIER_DESCRIPTOR
{
    byte bLength;               // Size of this descriptor
    byte bType;                 // Type, always USB_DESCRIPTOR_DEVICE_QUALIFIER
    word bcdUSB;                // USB spec version, in BCD
    byte bDeviceClass;          // Device class code
    byte bDeviceSubClass;       // Device sub-class code
    byte bDeviceProtocol;       // Device protocol
    byte bMaxPacketSize0;       // EP0, max packet size
    byte bNumConfigurations;    // Number of "other-speed" configurations
    byte bReserved;             // Always zero (0)
} USB_DEVICE_QUALIFIER_DESCRIPTOR;

//=================================================================================
//Generic Configuration
//=================================================================================
typedef struct __attribute__ ((__packed__)) _CONFIG_GEN
{
 USB_CONFIGURATION_DESCRIPTOR dev_conf;
 USB_INTERFACE_DESCRIPTOR dev_int;
} CONFIG_GEN;

//=================================================================================
//HID
//=================================================================================
typedef struct __attribute__ ((__packed__)) _USB_HID_DESCRIPTOR
{
    byte bLength;
    byte bDescriptorType;
    word bcdHID;
    byte bCountryCode;
    byte bNumDescriptors;
    byte bRPDescriptorType;
    word wRPDescriptorLength;
} USB_HID_DESCRIPTOR;

//Configuration
typedef struct __attribute__ ((__packed__)) _CONFIG_HID
{
 USB_CONFIGURATION_DESCRIPTOR dev_conf;
 USB_INTERFACE_DESCRIPTOR dev_int;
 USB_HID_DESCRIPTOR dev_hid;
 USB_ENDPOINT_DESCRIPTOR dev_ep;
} CONFIG_HID;

//=================================================================================
//CDC
/* Functional Descriptor Structure - See CDC Specification 1.1 for details */
//=================================================================================

/* Header Functional Descriptor */
typedef struct __attribute__ ((__packed__)) _USB_CDC_HEADER_FN_DSC
{
    byte bFNLength;
    byte bDscType;
    byte bDscSubType;
    word bcdCDC;
} USB_CDC_HEADER_FN_DSC;

/* Abstract Control Management Functional Descriptor */
typedef struct __attribute__ ((__packed__)) _USB_CDC_ACM_FN_DSC
{
    byte bFNLength;
    byte bDscType;
    byte bDscSubType;
    byte bmCapabilities;
} USB_CDC_ACM_FN_DSC;

/* Union Functional Descriptor */
typedef struct __attribute__ ((__packed__)) _USB_CDC_UNION_FN_DSC
{
    byte bFNLength;
    byte bDscType;
    byte bDscSubType;
    byte bMasterIntf;
    byte bSaveIntf0;
} USB_CDC_UNION_FN_DSC;

/* Call Management Functional Descriptor */
typedef struct __attribute__ ((__packed__)) _USB_CDC_CALL_MGT_FN_DSC
{
    byte bFNLength;
    byte bDscType;
    byte bDscSubType;
    byte bmCapabilities;
    byte bDataInterface;
} USB_CDC_CALL_MGT_FN_DSC;

//Configuration
typedef struct __attribute__ ((__packed__)) _CONFIG_CDC
{
 USB_CONFIGURATION_DESCRIPTOR dev_conf0;
 USB_INTERFACE_DESCRIPTOR dev_int0;
 USB_CDC_HEADER_FN_DSC cdc_header;
 USB_CDC_CALL_MGT_FN_DSC cdc_call_mgt;
 USB_CDC_ACM_FN_DSC cdc_acm;
 USB_CDC_UNION_FN_DSC cdc_union;
 USB_ENDPOINT_DESCRIPTOR dev_ep0;
 USB_INTERFACE_DESCRIPTOR dev_int1;
 USB_ENDPOINT_DESCRIPTOR dev_ep1;
 USB_ENDPOINT_DESCRIPTOR dev_ep2;
} CONFIG_CDC;


//=================================================================================
// CCID
//=================================================================================

#define CCID_IN_EP                          0x84U  /* EP1 for data IN */
#define CCID_OUT_EP                         0x04U  /* EP1 for data OUT */
#define CCID_CMD_EP                         0x85U  /* EP2 for CDC commands */

#define CCID_DATA_PACKET_SIZE               64

/*CCID specification version 1.10*/
#define CCID1_10                               0x0110
#define SMART_CARD_DEVICE_CLASS                0x0B
/* Smart Card Device Class Descriptor Type */
#define CCID_DECRIPTOR_TYPE                    0x21
/* Table 5.3-1 Summary of CCID Class Specific Request */
#define CCIDGENERICREQ_ABORT                    0x01
#define CCIDGENERICREQ_GET_CLOCK_FREQUENCIES    0x02
#define CCIDGENERICREQ_GET_DATA_RATES           0x03
/* 6.1 Command Pipe, Bulk-OUT Messages */
#define PC_TO_RDR_ICCPOWERON                   0x62
#define PC_TO_RDR_ICCPOWEROFF                  0x63
#define PC_TO_RDR_GETSLOTSTATUS                0x65
#define PC_TO_RDR_XFRBLOCK                     0x6F
#define PC_TO_RDR_GETPARAMETERS                0x6C
#define PC_TO_RDR_RESETPARAMETERS              0x6D
#define PC_TO_RDR_SETPARAMETERS                0x61
#define PC_TO_RDR_ESCAPE                       0x6B
#define PC_TO_RDR_ICCCLOCK                     0x6E
#define PC_TO_RDR_T0APDU                       0x6A
#define PC_TO_RDR_SECURE                       0x69
#define PC_TO_RDR_MECHANICAL                   0x71
#define PC_TO_RDR_ABORT                        0x72
#define PC_TO_RDR_SETDATARATEANDCLOCKFREQUENCY 0x73
/* 6.2 Response Pipe, Bulk-IN Messages */
#define RDR_TO_PC_DATABLOCK                    0x80
#define RDR_TO_PC_SLOTSTATUS                   0x81
#define RDR_TO_PC_PARAMETERS                   0x82
#define RDR_TO_PC_ESCAPE                       0x83
#define RDR_TO_PC_DATARATEANDCLOCKFREQUENCY    0x84
/* 6.3 Interrupt-IN Messages */
#define RDR_TO_PC_NOTIFYSLOTCHANGE             0x50
#define RDR_TO_PC_HARDWAREERROR                0x51
/* Table 6.2-2 Slot error register when bmCommandStatus = 1 */
#define CMD_ABORTED                            0xFF
#define ICC_MUTE                               0xFE
#define XFR_PARITY_ERROR                       0xFD
#define XFR_OVERRUN                            0xFC
#define HW_ERROR                               0xFB
#define BAD_ATR_TS                             0xF8
#define BAD_ATR_TCK                            0xF7
#define ICC_PROTOCOL_NOT_SUPPORTED             0xF6
#define ICC_CLASS_NOT_SUPPORTED                0xF5
#define PROCEDURE_BYTE_CONFLICT                0xF4
#define DEACTIVATED_PROTOCOL                   0xF3
#define BUSY_WITH_AUTO_SEQUENCE                0xF2
#define PIN_TIMEOUT                            0xF0
#define PIN_CANCELLED                          0xEF
#define CMD_SLOT_BUSY                          0xE0
/* CCID rev 1.1, p.27 */
#define VOLTS_AUTO                             0x00
#define VOLTS_5_0                              0x01
#define VOLTS_3_0                              0x02
#define VOLTS_1_8                              0x03
/* 6.3.1 RDR_to_PC_NotifySlotChange */
#define ICC_NOT_PRESENT                        0x00
#define ICC_PRESENT                            0x01
#define ICC_CHANGE                             0x02
#define ICC_INSERTED_EVENT                     (ICC_PRESENT+ICC_CHANGE)


typedef struct __attribute__ ((__packed__)) _USB_ICC_DESCRIPTOR
{
    byte bFNLength;
    byte bDscType;
    word bcdCCID;
    byte bMaxSlotIndex;
    byte bVoltageSupport;
    dword dwProtocols;
    dword dwDefaultClock;
    dword dwMaximumClock;
    byte bNumClockSupported;
    dword dwDataRate;
    dword dwMaxDataRate;
    byte bNumDataRateSupported;
    dword dwMaxIFSD;
    dword dwSynchProtocols;
    dword dwMechanical;
    dword dwFeatures;
    dword dwMaxCCIDMessageLength;
    byte bClassGetResponse;
    byte bClassEnvelope;
    word wLCDLayout;
    byte bPinSupport;
    byte bMaxCCIDBusySlots;
} USB_ICC_DESCRIPTOR;

//Configuration
typedef struct __attribute__ ((__packed__)) _CONFIG_CCID
{
 USB_CONFIGURATION_DESCRIPTOR dev_conf0;
 USB_INTERFACE_DESCRIPTOR dev_int0;
 USB_ICC_DESCRIPTOR icc_desc0;
 USB_ENDPOINT_DESCRIPTOR dev_ep0;
 USB_ENDPOINT_DESCRIPTOR dev_ep1;
 USB_ENDPOINT_DESCRIPTOR dev_ep2;
} CONFIG_CCID;

//=================================================================================
//USBIP data struct 

typedef struct  __attribute__ ((__packed__)) _OP_REQ_DEVLIST
{
 word version;
 word command;
 int status;
} OP_REQ_DEVLIST;


typedef struct  __attribute__ ((__packed__)) _OP_REP_DEVLIST_HEADER
{
word version;
word command;
int status;
int nExportedDevice;
}OP_REP_DEVLIST_HEADER;

//================= for each device
typedef struct  __attribute__ ((__packed__)) _OP_REP_DEVLIST_DEVICE
{
char usbPath[256];
char busID[32];
int busnum;
int devnum;
int speed;
word idVendor;
word idProduct;
word bcdDevice;
byte bDeviceClass;
byte bDeviceSubClass;
byte bDeviceProtocol;
byte bConfigurationValue;
byte bNumConfigurations; 
byte bNumInterfaces;
}OP_REP_DEVLIST_DEVICE;

//================== for each interface
typedef struct  __attribute__ ((__packed__)) _OP_REP_DEVLIST_INTERFACE
{
byte bInterfaceClass;
byte bInterfaceSubClass;
byte bInterfaceProtocol;
byte padding;
}OP_REP_DEVLIST_INTERFACE;

typedef struct  __attribute__ ((__packed__)) _OP_REP_DEVLIST
{
OP_REP_DEVLIST_HEADER      header;
OP_REP_DEVLIST_DEVICE      device; //only one!
OP_REP_DEVLIST_INTERFACE   *interfaces;
}OP_REP_DEVLIST;

typedef struct  __attribute__ ((__packed__)) _OP_REQ_IMPORT
{
word version;
word command;
int status;
char busID[32];
}OP_REQ_IMPORT;


typedef struct  __attribute__ ((__packed__)) _OP_REP_IMPORT
{
word version;
word command;
int  status;
//------------- if not ok, finish here
char usbPath[256];
char busID[32];
int busnum;
int devnum;
int speed;
word idVendor;
word idProduct;
word bcdDevice;
byte bDeviceClass;
byte bDeviceSubClass;
byte bDeviceProtocol;
byte bConfigurationValue;
byte bNumConfigurations;
byte bNumInterfaces;
}OP_REP_IMPORT;



typedef struct  __attribute__ ((__packed__)) _USBIP_CMD_SUBMIT
{
int command;
int seqnum;
int devid;
int direction;
int ep;
int transfer_flags;
int transfer_buffer_length;
int start_frame;
int number_of_packets;
int interval;
long long setup;
}USBIP_CMD_SUBMIT;

/*
+  Allowed transfer_flags  | value      | control | interrupt | bulk     | isochronous
+ -------------------------+------------+---------+-----------+----------+-------------
+  URB_SHORT_NOT_OK        | 0x00000001 | only in | only in   | only in  | no
+  URB_ISO_ASAP            | 0x00000002 | no      | no        | no       | yes
+  URB_NO_TRANSFER_DMA_MAP | 0x00000004 | yes     | yes       | yes      | yes
+  URB_NO_FSBR             | 0x00000020 | yes     | no        | no       | no
+  URB_ZERO_PACKET         | 0x00000040 | no      | no        | only out | no
+  URB_NO_INTERRUPT        | 0x00000080 | yes     | yes       | yes      | yes
+  URB_FREE_BUFFER         | 0x00000100 | yes     | yes       | yes      | yes
+  URB_DIR_MASK            | 0x00000200 | yes     | yes       | yes      | yes
*/

typedef struct  __attribute__ ((__packed__)) _USBIP_RET_SUBMIT
{
int command;
int seqnum;
int devid;
int direction;
int ep;
int status;
int actual_length;
int start_frame;
int number_of_packets;
int error_count; 
long long setup;
}USBIP_RET_SUBMIT;


typedef struct  __attribute__ ((__packed__)) _USBIP_CMD_UNLINK
{
int command;
int seqnum;
int devid;
int direction;
int ep;
int seqnum_urb;
}USBIP_CMD_UNLINK;


typedef struct  __attribute__ ((__packed__)) _USBIP_RET_UNLINK
{
int command;
int seqnum;
int devid;
int direction;
int ep;
int status;
}USBIP_RET_UNLINK;



typedef struct  __attribute__ ((__packed__)) _StandardDeviceRequest
{
  byte bmRequestType;
  byte bRequest;
  byte wValue0;
  byte wValue1;
  byte wIndex0;
  byte wIndex1;
  word wLength;
}StandardDeviceRequest;


void send_usb_req(int sockfd, USBIP_RET_SUBMIT * usb_req, char * data, unsigned int size, unsigned int status);
void usbip_run (const USB_DEVICE_DESCRIPTOR *dev_dsc);

//implemented by user
extern const USB_DEVICE_DESCRIPTOR dev_dsc;
extern const USB_DEVICE_QUALIFIER_DESCRIPTOR  dev_qua;
extern const char * configuration;
extern const USB_INTERFACE_DESCRIPTOR *interfaces[];
extern const unsigned char *strings[];

void handle_data(int sockfd, USBIP_RET_SUBMIT *usb_req, int bl);
void handle_unknown_control(int sockfd, StandardDeviceRequest * control_req, USBIP_RET_SUBMIT *usb_req);
