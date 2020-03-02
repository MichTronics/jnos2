/* AX25 link callsign monitoring. Also contains beginnings of
 * an automatic link quality monitoring scheme (incomplete)
 *
 * Copyright 1991 Phil Karn, KA9Q
 */
#include <ctype.h>
#include "global.h"
#include <time.h>
#ifdef AX25
#include "mbuf.h"
#include "iface.h"
#include "ax25.h"
#include "ip.h"
#include "timer.h"
  
#define iscallsign(c) ((isupper(c)) || (isdigit(c)) || (c ==' '))
int axheard_filter_flag = AXHEARD_PASS;
  
static struct lq *al_create __ARGS((struct iface *ifp,char *addr));
static struct ld *ad_lookup __ARGS((struct iface *ifp,char *addr,int sort));
static struct ld *ad_create __ARGS((struct iface *ifp,char *addr));
struct lq *Lq;
struct ld *Ld;
  
#ifdef  notdef
/* Send link quality reports to interface */
void
genrpt(ifp)
struct iface *ifp;
{
    struct mbuf *bp;
    register char *cp;
    int i;
    struct lq *lp;
    int maxentries,nentries;
  
    maxentries = (Paclen - LQHDR) / LQENTRY;
    if((bp = alloc_mbuf(Paclen)) == NULLBUF)
        return;
    cp = bp->data;
    nentries = 0;
  
    /* Build and emit header */
    cp = putlqhdr(cp,LINKVERS,Ip_addr);
  
    /* First entry is for ourselves. Since we're examining the Axsent
     * variable before we've sent this frame, add one to it so it'll
     * match the receiver's count after he gets this frame.
     */
    cp = putlqentry(cp,ifp->hwaddr,Axsent+1);
    nentries++;
  
    /* Now add entries from table */
    for(lp = lq;lp != NULLLQ;lp = lp->next){
        cp = putlqentry(cp,&lp->addr,lp->currxcnt);
        if(++nentries >= MAXENTRIES){
            /* Flush */
            bp->cnt = nentries*LQENTRY + LQHDR;
            ax_output(ifp,Ax25multi[0],ifp->hwaddr,PID_LQ,bp);
            if((bp = alloc_mbuf(Paclen)) == NULLBUF)
                return;
            cp = bp->data;
        }
    }
    if(nentries > 0){
        bp->cnt = nentries*LQENTRY + LQHDR;
        ax_output(ifp,Ax25multi[0],ifp->hwaddr,LQPID,bp);
    } else {
        free_p(bp);
    }
}
  
/* Pull the header off a link quality packet */
void
getlqhdr(hp,bpp)
struct lqhdr *hp;
struct mbuf **bpp;
{
    hp->version = pull16(bpp);
    hp->ip_addr = pull32(bpp);
}
  
/* Put a header on a link quality packet.
 * Return pointer to buffer immediately following header
 */
char *
putlqhdr(cp,version,ip_addr)
register char *cp;
int16 version;
int32 ip_addr;
{
    cp = put16(cp,version);
    return put32(cp,ip_addr);
}
  
/* Pull an entry off a link quality packet */
void
getlqentry(ep,bpp)
struct lqentry *ep;
struct mbuf **bpp;
{
    pullup(bpp,ep->addr,AXALEN);
    ep->count = pull32(bpp);
}
  
/* Put an entry on a link quality packet
 * Return pointer to buffer immediately following header
 */
char *
putlqentry(cp,addr,count)
char *cp;
char *addr;
int32 count;
{
    memcpy(cp,addr,AXALEN);
    cp += AXALEN;
    return put32(cp,count);
}
#endif
  
/* Log the source address of an incoming packet */
void
logsrc(ifp,addr)
struct iface *ifp;
char *addr;
{
    register struct lq *lp;
  
    if(axheard_filter_flag & AXHEARD_NOSRC || !(ifp->flags & LOG_AXHEARD))
        return;
    {
        register unsigned char c;
        register int i = 0;
        while(i < AXALEN-1){
            c = *(addr+i);
            c >>= 1;
            if(!iscallsign(c))
                return;
            i++;
        }
    }
  
    if((lp = al_lookup(ifp,addr,1)) == NULLLQ)
        if((lp = al_create(ifp,addr)) == NULLLQ)
            return;
    lp->currxcnt++;
    lp->time = secclock();
}
/* Log the destination address of an incoming packet */
void
logdest(ifp,addr)
struct iface *ifp;
char *addr;
{
    register struct ld *lp;
  
    if(axheard_filter_flag & AXHEARD_NODST || !(ifp->flags & LOG_AXHEARD))
        return;
    {
        register unsigned char c;
        register int i = 0;
        while(i < AXALEN-1){
            c = *(addr+i);
            c >>= 1;
            if(!iscallsign(c))
                return;
            i++;
        }
    }
  
    if((lp = ad_lookup(ifp,addr,1)) == NULLLD)
        if((lp = ad_create(ifp,addr)) == NULLLD)
            return;
    lp->currxcnt++;
    lp->time = secclock();
}
/* Look up an entry in the source data base */
struct lq *
al_lookup(ifp,addr,sort)
struct iface *ifp;
char *addr;
int sort;
{
    register struct lq *lp;
    struct lq *lplast = NULLLQ;
  
    for(lp = Lq;lp != NULLLQ;lplast = lp,lp = lp->next){
        if((lp->iface == ifp) && addreq(lp->addr,addr)){
            if(sort && lplast != NULLLQ){
                /* Move entry to top of list */
                lplast->next = lp->next;
                lp->next = Lq;
                Lq = lp;
            }
            return lp;
        }
    }
    return NULLLQ;
}
  
extern int Maxax25heard;
  
/* Create a new entry in the source database */
/* If there are too many entries, override the oldest one - WG7J */
static struct lq *
al_create(ifp,addr)
struct iface *ifp;
char *addr;
{
    extern int numal;        /* in ax25cmd.c - K5JB */
    register struct lq *lp;
    struct lq *lplast = NULLLQ;
  
    if(Maxax25heard && numal == Maxax25heard) {
        /* find and use last one in list */
        for(lp = Lq;lp->next != NULLLQ;lplast = lp,lp = lp->next);
        /* delete entry from end */
        if(lplast)
            lplast->next = NULLLQ;
        else    /* Only one entry, and maxax25heard = 1 ! */
            Lq = NULLLQ;
        lp->currxcnt = 0;
    } else {    /* create a new entry */
        numal++;
        lp = (struct lq *)callocw(1,sizeof(struct lq));
    }
    memcpy(lp->addr,addr,AXALEN);
    lp->iface = ifp;
    lp->next = Lq;
    Lq = lp;
  
    return lp;
}
  
/* Look up an entry in the destination database */
static struct ld *
ad_lookup(ifp,addr,sort)
struct iface *ifp;
char *addr;
int sort;
{
    register struct ld *lp;
    struct ld *lplast = NULLLD;
  
    for(lp = Ld;lp != NULLLD;lplast = lp,lp = lp->next){
        if((lp->iface == ifp) && addreq(lp->addr,addr)){
            if(sort && lplast != NULLLD){
                /* Move entry to top of list */
                lplast->next = lp->next;
                lp->next = Ld;
                Ld = lp;
            }
            return lp;
        }
    }
    return NULLLD;
}
/* Create a new entry in the destination database */
static struct ld *
ad_create(ifp,addr)
struct iface *ifp;
char *addr;
{
    extern int numad;    /* In ax25cmd.c - K5JB */
    register struct ld *lp;
    struct ld *lplast = NULLLD;
  
    if(Maxax25heard && numad == Maxax25heard) { /* find and use last one in list */
        for(lp = Ld;lp->next != NULLLD;lplast = lp,lp = lp->next);
        /* delete entry from end */
        if(lplast)
            lplast->next = NULLLD;
        else
            Ld = NULLLD;
        lp->currxcnt = 0;
    } else {    /* create a new entry */
        numad++;
        lp = (struct ld *)callocw(1,sizeof(struct ld));
    }
    memcpy(lp->addr,addr,AXALEN);
    lp->iface = ifp;
    lp->next = Ld;
    Ld = lp;
  
    return lp;
}

#ifdef	BACKUP_AXHEARD

/*
 * 21Jan2020, Maiko (VE4KLM), New functions to save and restore axheard lists
 *  (called from ax25cmd.c - but in here because I need al_create() function)
 *
 * Requested by Martijn (PD2NLX) in the Netherlands :)
 *
 * 25Jan2020, Maiko, completed save function
 *
 * 27Jan2020, Maiko, completed load function
 * 
 * 28Jan2020, Maiko, merging doax commands in ax25cmd.c, so we
 * no longer need to have full argument style function calls.
 *
int doaxhsave (int argc, char **argv, void *p)
int doaxhload (int argc, char **argv, void *p)
 *
 */

int doaxhsave (void)
{
	char tmp[AXBUF];
	struct lq *lp;
	time_t now;
	FILE *fp;

	if ((fp = fopen ("AxHeardFile", "w+")) == NULLFILE)
	{
		log (-1, "Can't write AxHeardFile");
		return 1;
	}

	/*
	 * 27Jan2020, Maiko, Forgot to save a timestamp of when this file gets
	 * created, we will need this to make sure the time stamps on a future
	 * load are 'accurate' - timestamps are based on the JNOS 'Starttime',
	 * not the epoc or whatever they call it, going back to the 1970 era.
	 */

	time (&now); fprintf (fp, "%ld\n", (long)now);
  
	for (lp = Lq;lp != NULLLQ; lp = lp->next)
	{
		// SAVE these : something to identify iface, lp->addr, lp->time, lp->currxcnt

		fprintf (fp, "%s %s %d %d\n", lp->iface->name, pax25 (tmp, lp->addr), lp->time, lp->currxcnt);
	}

	fclose (fp);

	return 0;
}

int doaxhload (void)
{
	char iobuffer[80];
	char ifacename[30], callsign[12];
	char thecall[AXALEN];
	int32 axetime, count;
	struct iface *ifp;
	struct lq *lp;
	long time_gap;
	time_t now;
	FILE *fp;

	if ((fp = fopen ("AxHeardFile", "r")) == NULLFILE)
	{
		log (-1, "can't read AxHeardFile");
		return 1;
	}

	/*
	 * 27Jan2020, Maiko, Make sure to read the timestamp at the
	 * top or else we get gaps in the time stamps.
	 */
	if (fgets (iobuffer, sizeof(iobuffer) - 2, fp) == NULLCHAR)
	{
		log (-1, "can't read time stamp from AxHeardFile");
		fclose (fp);
		return 1;
	}	

	time (&now);
	sscanf (iobuffer, "%ld", &time_gap);
	time_gap = (long)now - time_gap;	/* time from when file was last saved */

	log (-1, "adjusting time entries by %d seconds", time_gap);

	while (fgets (iobuffer, sizeof(iobuffer) - 2, fp) != NULLCHAR)
	{
		sscanf (iobuffer, "%s %s %u %u", ifacename, callsign, &axetime, &count);

 		// log (-1, "%s %s %d %d", ifacename, callsign, axetime, count); 

		if ((ifp = if_lookup (ifacename)) == NULLIF)
			log (-1, "unable to lookup iface [%s]", ifacename);

		else if (setcall (thecall, callsign) == -1)
			log (-1, "unable to set call [%s]", callsign);

		/* if the call is already there, then don't overwrite it of course */
   		else if ((lp = al_lookup (ifp, thecall, 1)) == NULLLQ)
		{
			if ((lp = al_create (ifp, thecall)) == NULLLQ)
				log (-1, "unable to create Lq entry");
			else
			{
				lp->currxcnt = count;
		/*
		 * 27Jan2020, Maiko, This won't be accurate, need to find a way to offset
		 * the last saved time of axheard file with 'now', so that is why I have
		 * the time_gap value added to each time we read in.
		 *
		 * NOW - what will be interesting is that since JNOS logs these times
		 * based on secclock(), since JNOS started, if the corrected times are
		 * actually greater then the time JNOS has been running, we run into a
		 * problem where axheard can show negative time values, and they will
		 * actually run the wrong way each time we do a 'ax25 heard', so this
		 * requires some additional code work in ax25cmd.c, working nicely.
		 */
				lp->time = axetime + time_gap;
			}
		}
	}

	fclose (fp);
  
	return 0;
}

#endif /* BACKUP_AXHEARD */

#endif /* AX25 */

