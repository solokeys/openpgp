/* ########################################################################

   USBIP hardware emulation 

   ########################################################################

   Copyright (c) : 2016  Luis Claudio Gambôa Lopes

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

//system headers dependent


#include"usbip.h"


#ifdef _DEBUG
void print_recv(char* buff,int size,const char* desc)
{
    int i,j;
    
    printf("----------recv  %s (%i)-----------\n",desc,size);
            
    j=1;
    for(i=0; i< size; i++)
    {
        printf("0x%02X ",(unsigned char)buff[i]);
        if(j > 7)
        {
           printf("\n"); 
           j=0; 
        };
        j++;
    }
           
          
    printf("\n-------------------------\n");    
}
#endif

#ifndef LINUX
WORD wVersionRequested = 2;
WSADATA wsaData;
#endif

void handle_device_list(const USB_DEVICE_DESCRIPTOR *dev_dsc, OP_REP_DEVLIST *list)
{
  CONFIG_GEN * conf= (CONFIG_GEN *)configuration;   
  int i;
  list->header.version=htons(273);
  list->header.command=htons(5);
  list->header.status=0;
  list->header.nExportedDevice=htonl(1);
  memset(list->device.usbPath,0,256);
  strcpy(list->device.usbPath,"/sys/devices/pci0000:00/0000:00:01.2/usb1/1-1");
  memset(list->device.busID,0,32);
  strcpy(list->device.busID,"1-1");
  list->device.busnum=htonl(1);
  list->device.devnum=htonl(2);
  list->device.speed=htonl(2);
  list->device.idVendor=htons(dev_dsc->idVendor);
  list->device.idProduct=htons(dev_dsc->idProduct);
  list->device.bcdDevice=htons(dev_dsc->bcdDevice);
  list->device.bDeviceClass=dev_dsc->bDeviceClass;
  list->device.bDeviceSubClass=dev_dsc->bDeviceSubClass;
  list->device.bDeviceProtocol=dev_dsc->bDeviceProtocol;
  list->device.bConfigurationValue=conf->dev_conf.bConfigurationValue;
  list->device.bNumConfigurations=dev_dsc->bNumConfigurations; 
  list->device.bNumInterfaces=conf->dev_conf.bNumInterfaces;
  list->interfaces=malloc(list->device.bNumInterfaces*sizeof(OP_REP_DEVLIST_INTERFACE));
  for(i=0;i<list->device.bNumInterfaces;i++)
  {     
    list->interfaces[i].bInterfaceClass=interfaces[i]->bInterfaceClass;
    list->interfaces[i].bInterfaceSubClass=interfaces[i]->bInterfaceSubClass;
    list->interfaces[i].bInterfaceProtocol=interfaces[i]->bInterfaceProtocol;
    list->interfaces[i].padding=0;
  }
};

void handle_attach(const USB_DEVICE_DESCRIPTOR *dev_dsc, OP_REP_IMPORT *rep)
{
  CONFIG_GEN * conf= (CONFIG_GEN *)configuration; 
    
  rep->version=htons(273);
  rep->command=htons(3);
  rep->status=0;
  memset(rep->usbPath,0,256);
  strcpy(rep->usbPath,"/sys/devices/pci0000:00/0000:00:01.2/usb1/1-1");
  memset(rep->busID,0,32);
  strcpy(rep->busID,"1-1");
  rep->busnum=htonl(1);
  rep->devnum=htonl(2);
  rep->speed=htonl(2);
  rep->idVendor=dev_dsc->idVendor;
  rep->idProduct=dev_dsc->idProduct;
  rep->bcdDevice=dev_dsc->bcdDevice;
  rep->bDeviceClass=dev_dsc->bDeviceClass;
  rep->bDeviceSubClass=dev_dsc->bDeviceSubClass;
  rep->bDeviceProtocol=dev_dsc->bDeviceProtocol;
  rep->bNumConfigurations=dev_dsc->bNumConfigurations; 
  rep->bConfigurationValue=conf->dev_conf.bConfigurationValue;
  rep->bNumInterfaces=conf->dev_conf.bNumInterfaces;
}

void pack(int * data, int size)
{
   int i;
   size=size/4;
   for(i=0;i<size;i++)
   {
      data[i]=htonl(data[i]);
   }
   //swap setup
   i=data[size-1];
   data[size-1]=data[size-2];
   data[size-2]=i;
}  
             
void unpack(int * data, int size)
{
   int i;
   size=size/4;
   for(i=0;i<size;i++)
   {
      data[i]=ntohl(data[i]);
   }
   //swap setup
   i=data[size-1];
   data[size-1]=data[size-2];
   data[size-2]=i;
}  


void send_usb_req(int sockfd, USBIP_RET_SUBMIT * usb_req, char * data, unsigned int size, unsigned int status)
{
        usb_req->command=0x3;
        usb_req->status=status;
        usb_req->actual_length=size;
        usb_req->start_frame=0x0;
        usb_req->number_of_packets=0x0;
	
        usb_req->setup=0x0;
        usb_req->devid=0x0;
	usb_req->direction=0x0;
        usb_req->ep=0x0;    
    
        pack((int *)usb_req, sizeof(USBIP_RET_SUBMIT));
 
        if (send (sockfd, (char *)usb_req, sizeof(USBIP_RET_SUBMIT), 0) != sizeof(USBIP_RET_SUBMIT))
        {
          printf ("send error : %s \n", strerror (errno));
          exit(-1);
        };

        if(size > 0)
        {
           if (send (sockfd, data, size, 0) != size)
           {
             printf ("send error : %s \n", strerror (errno));
             exit(-1);
           };
        }
} 
            
int handle_get_descriptor(int sockfd, StandardDeviceRequest * control_req, USBIP_RET_SUBMIT *usb_req)
{
  int handled = 0;
  printf("handle_get_descriptor %u [%u]\n",control_req->wValue1,control_req->wValue0 );
  if(control_req->wValue1 == 0x1) // Device
  {
    printf("Device\n");  
    handled = 1;
    send_usb_req(sockfd,usb_req, (char *)&dev_dsc, sizeof(USB_DEVICE_DESCRIPTOR)/*control_req->wLength*/, 0);
   } 
   if(control_req->wValue1 == 0x2) // configuration
   {
     printf("Configuration\n");  
     handled = 1;
     send_usb_req(sockfd,usb_req, (char *) configuration, control_req->wLength ,0);
   }
   if(control_req->wValue1 == 0x3) // string
   {
     char str[255];
     int i;
     memset(str,0,255); 
     for(i=0;i< (*strings[control_req->wValue0]/2) -1;i++)
        str[i]=strings[control_req->wValue0][i*2+2];
     printf("String (%s)\n",str);  
     handled = 1;
     send_usb_req(sockfd,usb_req, (char *) strings[control_req->wValue0] ,*strings[control_req->wValue0]  ,0);
   }
   if(control_req->wValue1 == 0x6) // qualifier
   {
     printf("Qualifier\n");  
     handled = 1;
     send_usb_req(sockfd,usb_req, (char *) &dev_qua , control_req->wLength ,0);
   }
   if(control_req->wValue1 == 0xA) // config status ???
   {
     printf("Unknow\n");  
     handled = 1;
     send_usb_req(sockfd,usb_req,"",0,1);        
   }  
   return handled;
}

int handle_set_configuration(int sockfd, StandardDeviceRequest * control_req, USBIP_RET_SUBMIT *usb_req)
{
  int handled = 0;
  printf("handle_set_configuration %u[%u]\n",control_req->wValue1,control_req->wValue0 );
  handled = 1;
  send_usb_req(sockfd, usb_req, "", 0, 0);        
  return handled;
}

//http://www.usbmadesimple.co.uk/ums_4.htm

void handle_usb_control(int sockfd, USBIP_RET_SUBMIT *usb_req)
{
        int handled = 0;
        StandardDeviceRequest control_req;
#ifdef LINUX
        printf("%016llX\n",usb_req->setup); 
#else
        printf("%016I64X\n",usb_req->setup); 
#endif
        control_req.bmRequestType=  (usb_req->setup & 0xFF00000000000000)>>56;  
        control_req.bRequest=       (usb_req->setup & 0x00FF000000000000)>>48;  
        control_req.wValue0=        (usb_req->setup & 0x0000FF0000000000)>>40;  
        control_req.wValue1=        (usb_req->setup & 0x000000FF00000000)>>32;
        control_req.wIndex0=        (usb_req->setup & 0x00000000FF000000)>>24; 
        control_req.wIndex1=        (usb_req->setup & 0x0000000000FF0000)>>16;
        control_req.wLength=   ntohs(usb_req->setup & 0x000000000000FFFF);  
        printf("  UC Request Type %u\n",control_req.bmRequestType);
        printf("  UC Request %u\n",control_req.bRequest);
        printf("  UC Value  %u[%u]\n",control_req.wValue1,control_req.wValue0);
        printf("  UCIndex  %u-%u\n",control_req.wIndex1,control_req.wIndex0);
        printf("  UC Length %u\n",control_req.wLength);
        
        if(control_req.bmRequestType == 0x80) // Host Request
        {
          if(control_req.bRequest == 0x06) // Get Descriptor
          {
            handled = handle_get_descriptor(sockfd, &control_req, usb_req);
          }
          if(control_req.bRequest == 0x00) // Get STATUS
          {
            char data[2];
            data[0]=0x01;
            data[1]=0x00;
            send_usb_req(sockfd,usb_req, data, 2 , 0);        
            handled = 1;
            printf("GET_STATUS\n");   
          }
        }
        if(control_req.bmRequestType == 0x00) // 
        {
            if(control_req.bRequest == 0x09) // Set Configuration
            {
                handled = handle_set_configuration(sockfd, &control_req, usb_req);
            }
        }  
        if(control_req.bmRequestType == 0x01)
        { 
          if(control_req.bRequest == 0x0B) //SET_INTERFACE  
          {
            printf("SET_INTERFACE\n");   
            send_usb_req(sockfd,usb_req,"",0,1);
            handled=1; 
          } 
        }
        if(! handled)
            handle_unknown_control(sockfd, &control_req, usb_req);
}

           
void handle_usb_request(int sockfd, USBIP_RET_SUBMIT *ret, int bl)
{
   if(ret->ep == 0)
   {
      printf("#control requests\n");
      handle_usb_control(sockfd, ret);
   }
   else
   {
      printf("#data requests\n");
      handle_data(sockfd, ret, bl);
   }
};

void
usbip_run (const USB_DEVICE_DESCRIPTOR *dev_dsc)                                /* simple TCP server */
{
  struct sockaddr_in serv, cli;
  int listenfd, sockfd, nb;
#ifdef LINUX
  unsigned int clilen;
#else
  int clilen;
#endif
  unsigned char attached;



#ifndef LINUX
  WSAStartup (wVersionRequested, &wsaData);
  if (wsaData.wVersion != wVersionRequested)
    {
      fprintf (stderr, "\n Wrong version\n");
      exit (-1);
    }

#endif

  if ((listenfd = socket (PF_INET, SOCK_STREAM, 0)) < 0)
    {
      printf ("socket error : %s \n", strerror (errno));
      exit (1);
    };

  int reuse = 1;
  if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
      perror("setsockopt(SO_REUSEADDR) failed");

  memset (&serv, 0, sizeof (serv));
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = htonl (INADDR_ANY);
  serv.sin_port = htons (TCP_SERV_PORT);

  if (bind (listenfd, (sockaddr *) & serv, sizeof (serv)) < 0)
    {
      printf ("bind error : %s \n", strerror (errno));
      exit (1);
    };

  if (listen (listenfd, SOMAXCONN) < 0)
    {
      printf ("listen error : %s \n", strerror (errno));
      exit (1);
    };

  for (;;)
    {

      clilen = sizeof (cli);
      if (
          (sockfd =
           accept (listenfd, (sockaddr *) & cli,  & clilen)) < 0)
        {
          printf ("accept error : %s \n", strerror (errno));
          exit (1);
        };
        printf("Connection address:%s\n",inet_ntoa(cli.sin_addr));
        attached=0;
  
        while(1)
        {
          if(! attached)
          {
             OP_REQ_DEVLIST req;
             if ((nb = recv (sockfd, (char *)&req, sizeof(OP_REQ_DEVLIST), 0)) != sizeof(OP_REQ_DEVLIST))
             {
               //printf ("receive error : %s \n", strerror (errno));
               break;
             };
#ifdef _DEBUG
             print_recv((char *)&req, sizeof(OP_REQ_DEVLIST),"OP_REQ_DEVLIST");
#endif
             req.command=ntohs(req.command);
             printf("Header Packet\n");  
             printf("command: 0x%02X\n",req.command);
             if(req.command == 0x8005)
             {
               OP_REP_DEVLIST list;
               printf("list of devices\n");

               handle_device_list(dev_dsc,&list);

               if (send (sockfd, (char *)&list.header, sizeof(OP_REP_DEVLIST_HEADER), 0) != sizeof(OP_REP_DEVLIST_HEADER))
               {
                   printf ("send error : %s \n", strerror (errno));
                   break;
               };
               if (send (sockfd, (char *)&list.device, sizeof(OP_REP_DEVLIST_DEVICE), 0) != sizeof(OP_REP_DEVLIST_DEVICE))
               {
                   printf ("send error : %s \n", strerror (errno));
                   break;
               };
               if (send (sockfd, (char *)list.interfaces, sizeof(OP_REP_DEVLIST_INTERFACE)*list.device.bNumInterfaces, 0) != sizeof(OP_REP_DEVLIST_INTERFACE)*list.device.bNumInterfaces)
               {
                   printf ("send error : %s \n", strerror (errno));
                   break;
               };
               free(list.interfaces);
             }
             else if(req.command == 0x8003) 
             {
               char busid[32];
               OP_REP_IMPORT rep;
               printf("attach device\n");
               if ((nb = recv (sockfd, busid, 32, 0)) != 32)
               {
                 printf ("receive error : %s \n", strerror (errno));
                 break;
               };
#ifdef _DEBUG
             print_recv(busid, 32,"Busid");
#endif
               handle_attach(dev_dsc,&rep);
               if (send (sockfd, (char *)&rep, sizeof(OP_REP_IMPORT), 0) != sizeof(OP_REP_IMPORT))
               {
                   printf ("send error : %s \n", strerror (errno));
                   break;
               };
               attached = 1;
             }
          }
          else
          {
             printf("------------------------------------------------\n"); 
             printf("handles requests\n");
             USBIP_CMD_SUBMIT cmd;
             USBIP_RET_SUBMIT usb_req;
             if ((nb = recv (sockfd, (char *)&cmd, sizeof(USBIP_CMD_SUBMIT), 0)) != sizeof(USBIP_CMD_SUBMIT))
             {
               printf ("receive error : %s \n", strerror (errno));
               break;
             };
#ifdef _DEBUG
             print_recv((char *)&cmd, sizeof(USBIP_CMD_SUBMIT),"USBIP_CMD_SUBMIT");
#endif
             unpack((int *)&cmd,sizeof(USBIP_CMD_SUBMIT));               
             printf("usbip cmd %u\n",cmd.command);
             printf("usbip seqnum %u\n",cmd.seqnum);
             printf("usbip devid %u\n",cmd.devid);
             printf("usbip direction %u\n",cmd.direction);
             printf("usbip ep %u\n",cmd.ep);
             printf("usbip flags %u\n",cmd.transfer_flags);
             printf("usbip number of packets %u\n",cmd.number_of_packets);
             printf("usbip interval %u\n",cmd.interval);
#ifdef LINUX
             printf("usbip setup %llu\n",cmd.setup);
#else
             printf("usbip setup %I64u\n",cmd.setup);
#endif
             printf("usbip buffer lenght  %u\n",cmd.transfer_buffer_length);
             usb_req.command=0;
             usb_req.seqnum=cmd.seqnum;
             usb_req.devid=cmd.devid;
             usb_req.direction=cmd.direction;
             usb_req.ep=cmd.ep;
             usb_req.status=0;
             usb_req.actual_length=0;
             usb_req.start_frame=0;
             usb_req.number_of_packets=0;
             usb_req.error_count=0;
             usb_req.setup=cmd.setup;
             
             if(cmd.command == 1)
               handle_usb_request(sockfd, &usb_req, cmd.transfer_buffer_length);
             

             if(cmd.command == 2) //unlink urb
             {
                printf("####################### Unlink URB %u  (not working!!!)\n",cmd.transfer_flags);
             //FIXME
               /*              
                USBIP_RET_UNLINK ret;  
                printf("####################### Unlink URB %u\n",cmd.transfer_flags);
                ret.command=htonl(0x04);
                ret.devid=htonl(cmd.devid);
                ret.direction=htonl(cmd.direction);
                ret.ep=htonl(cmd.ep);
                ret.seqnum=htonl(cmd.seqnum);
                ret.status=htonl(1);
 
                if (send (sockfd, (char *)&ret, sizeof(USBIP_RET_UNLINK), 0) != sizeof(USBIP_RET_UNLINK))
                {
                  printf ("send error : %s \n", strerror (errno));
                  exit(-1);
                };
               */ 
             }

             if(cmd.command > 2)
             {
                printf("Unknown USBIP cmd!\n");  
                close (sockfd);
#ifndef LINUX
                WSACleanup ();
#endif
                return;  
             };
 
          } 
       }
       close (sockfd);
    };
#ifndef LINUX
  WSACleanup ();
#endif
};
