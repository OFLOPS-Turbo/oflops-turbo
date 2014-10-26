#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <netinet/in.h>

#include "control.h"
#include "utils.h"
#include "channel_info.h"

/**
 * setup the control channel of the oflops context.
 */
int setup_control_channel(oflops_context *ctx)
{
    struct sockaddr_in sin;
    struct sockaddr_in *sinptr;
    char buf[BUFLEN];
    unsigned int len;
    long flags;
    int one;
    struct ifreq ifr;


    fprintf(stderr, "Creating server socket...\n");
    ctx->listen_fd = socket( AF_INET, SOCK_STREAM, 0); //create genericl socket
    if(ctx->listen_fd == -1)
        perror_and_exit("Dying on socket",1);

    fprintf(stderr, "Setting SO_REUSE\n");
    one =1;

    /* in case this socket is in use and in active state then reuse it.
       (In case the progrem was terminated but didn;t shutdown properly
       it listening port )
     */
    if(setsockopt(ctx->listen_fd,SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
        perror_and_exit("Dying on setsockopt(SO_REUSEADDR)\n",1);
    assert(ctx->channels[OFLOPS_CONTROL].dev);

    /*
     * Get the name of the interface on which the socket was opened.
     */
    strncpy(ifr.ifr_name,ctx->channels[OFLOPS_CONTROL].dev,IFNAMSIZ);
    if( ioctl( ctx->listen_fd, SIOCGIFADDR, &ifr)  == -1 )
        perror_and_exit("ioctl() SIOCGIFADDR to dev",1);
    sinptr = (struct sockaddr_in *) & ifr.ifr_addr;	// convenience pointer


    sin.sin_family = AF_INET;
    sin.sin_addr =  sinptr->sin_addr;	// bind to the specific device
    sin.sin_port = htons(ctx->listen_port);
    fprintf(stderr, "Binding to port %d \n", ctx->listen_port);
    if(bind( ctx->listen_fd, (struct sockaddr *) &sin, sizeof(sin)))
        perror_and_exit("Dying on binding listen port",1);
    if(listen( ctx->listen_fd,16))
        perror_and_exit("Dying on listen",1);


    fprintf( stderr, "Waiting for a switch to connect...\n");
    len = sizeof(sin);
    if((ctx->control_fd=
                accept( ctx->listen_fd, (struct sockaddr *) &sin, &len)) == -1)
        perror_and_exit("accept",1);
    inet_ntop(AF_INET,&sin.sin_addr,buf,BUFLEN);
    fprintf( stderr, "Got connection from %s:%d \n",
             buf, htons(sin.sin_port));
    fprintf( stderr, "Setting control channel to non-blocking\n");

    // initialisation interactions with the switch have been pushed in module code for higher flexibility.
    /*
      struct ofp_header b;
      int count;
    //  uint8_t *buf;
      do {
      count = read(ctx->control_fd, &b, sizeof(struct ofp_header));

      //a dirty method to remove a non hello packet from the socket stream
      if(ntohs(b.length) > sizeof(struct ofp_header)) {
        count = sizeof(struct ofp_header);
    //    buf = (uint8_t *)malloc(ntohs(b.length) * sizeof(uint8_t));
        while( (count += read(ctx->control_fd, buf, ntohs(b.length) - count)) < ntohs(b.length) );
    //    free(buf);
      }
      }while(b.type != OFPT_HELLO);

      write(ctx->control_fd, &b, sizeof(struct ofp_header));
    */
    /*
      void *b;
      make_ofp_hello(&b);
      ((struct ofp_header *)b)->xid = 0x12345;
      free(b);
    */
    return 0;
}


