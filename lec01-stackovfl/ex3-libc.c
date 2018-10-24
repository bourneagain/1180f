/* CVE-2015-7547
     ref. https://sourceware.org/ml/libc-alpha/2016-02/msg00416.html (>1000 lines!)

@glibc-2.22
  getaddrinfo(): given a url, returns a set of addrinfo
    gaih_inet()
      gethostbyname4_r()
       : sends out parallel A (ipv4) and AAAA (ipv6) queries if PF_UNSPEC
*/
enum nss_status _nss_dns_gethostbyname4_r(...) {
   ...
   ansp = (querybuf *) alloca (2048);
   __libc_res_nsearch (&_res, name, C_IN, T_UNSPEC,
                       &ansp, 2048, &ansp,
                       &ansp2, &anssizp2, &resplen2, &ans2p_malloced);
   ...
}

/*
gethostbyname4_r()              <- alloca-ed
  __libc_res_nsearch()
    __libc_res_nquerydomain()
      __libc_res_nquery()
        __libc_res_nsend()
          send_dg()             <- overflow
*/
int __libc_res_nsend(...) {
next_ns:
  /* - buf/buflen: A query
     - buf2/buflen2: AAAA query
     - ansp: 'alloca-ed' buffer (host_buffer.buf->buf)
     - anssizp: 2048
     - anscp: ansp (fine to realloc if necessary)
     - ansp2: NULL (fine to malloc if necessary) */
  n = send_dg(statp, buf, buflen, buf2, buflen2,
              ansp, anssizp, &terrno,
              ns, &v_circuit, &gotsomewhere, ansp,
              ansp2, nansp2, resplen2, ansp2_malloced);
  /*
  When send_dg() returns:
    ansp  -> answer to A (or AAAA) query
    ansp2 -> answer to AAAA (or A) query 

  1) both are in stack (alloca)
  2) ansp in stack but ansp2 is in heap (no more space left after the first answer)
     (ans2p_malloced = 1)
  3) both are in heap (both answers were too big) 
     (ansp != anscp)
  */
  ...
  /* try another name server */
  if (n == 0 && (buf2 == NULL || *resplen2 == 0))
    goto next_ns;
}

/* (snippet of document in glibc-2.23)
   
   The send_dg function is responsible for sending a DNS query over UDP
   to the nameserver.
   
   The query stored in BUF of BUFLEN length is sent first followed by
   the query stored in BUF2 of BUFLEN2 length.  Queries are sent
   in parallel (default) or serially (RES_SINGLKUP or RES_SNGLKUPREOP).

   Answers to the query are stored firstly in *ANSP up to a max of
   *ANSSIZP bytes.  If more than *ANSSIZP bytes are needed and ANSCP
   is non-NULL (to indicate that modifying the answer buffer is allowed)
   then malloc is used to allocate a new response buffer and ANSCP and
   ANSP will both point to the new buffer.

   Answers to the query are stored secondly in *ANSP2 up to a max of
   *ANSSIZP2 bytes, with the actual response length stored in
   *RESPLEN2.  If more than *ANSSIZP bytes are needed and ANSP2
   is non-NULL (required for a second query) then malloc is used to
   allocate a new response buffer, *ANSSIZP2 is set to the new buffer
   size and *ANSP2_MALLOCED is set to 1.

   Note that the answers may arrive in any order from the server and
   therefore the first and second answer buffers may not correspond to
   the first and second queries.

   It is the caller's responsibility to free the malloc allocated
   buffers by detecting that the pointers have changed from their
   original values i.e. *ANSCP or *ANSP2 has changed.
*/
static int
send_dg(res_state statp,
	const u_char *buf, int buflen, const u_char *buf2, int buflen2,
	u_char **ansp, int *anssizp,
	int *terrno, int ns, int *v_circuit, int *gotsomewhere, u_char **anscp,
	u_char **ansp2, int *anssizp2, int *resplen2, int *ansp2_malloced)
{
	u_char *ans = *ansp;
	int orig_anssizp = *anssizp;

  /* both resps haven't arrived yet */
  int recvresp1 = 0;
  int recvresp2 = 0;
  
 wait:
  __poll (pfd, 1, 0);
  ...
  if (pfd[0].revents & POLLOUT) {...}
	else if (pfd[0].revents & POLLIN) {
    /* responses are arriving (on the wire). */
		int *thisanssizp;
		u_char **thisansp;
		int *thisresplenp;

		if ((recvresp1 | recvresp2) == 0) {
      /* We have not received any responses yet */
			thisanssizp = anssizp;
			thisansp = anscp ?: ansp;
			thisresplenp = &resplen;
		} else {
			if (*anssizp != MAXPACKET) {
				/* No buffer allocated for the first reply. We can
           try to use the rest of the user-provided buffer.  */
				*anssizp2 = orig_anssizp - resplen;
				*ansp2 = *ansp + resplen;
			} else {
				/* The first reply did not fit into the user-provided buffer.
           Maybe the second answer will.  */
				*anssizp2 = orig_anssizp;
				*ansp2 = *ansp;
			}

			thisanssizp = anssizp2;
			thisansp = ansp2;
			thisresplenp = resplen2;
		}

		if (*thisanssizp < MAXPACKET
		    /* Yes, we test ANSCP here. If we have two buffers
		       both will be allocatable. */
		    && anscp
		    && (ioctl (pfd[0].fd, FIONREAD, thisresplenp) < 0
            || *thisanssizp < *thisresplenp)) {
			u_char *newp = malloc(MAXPACKET);
			if (newp != NULL) {
				*anssizp = MAXPACKET;
				*thisansp = ans = newp;

        /* BUG:
            - failed to set *ansp to the new buffer
            - failed to set *thisanssizp to the new size

            *ansp -> allocaed (2048)
            *anssizp -> MAXPACKET */
        
				if (thisansp == ansp2)
				  *ansp2_malloced = 1;
			}
		}
		*thisresplenp = recvfrom(pfd[0].fd, (char*)*thisansp,
                             *thisanssizp, 0, &from, &fromlen);
		if (*thisresplenp <= 0)
      goto err_out;
    
		/* Mark which reply we received.  */
		if (recvresp1 == 0 && hp->id == anhp->id)
			recvresp1 = 1;
		else
			recvresp2 = 1;
    
		/* Repeat waiting if we have a second answer to arrive.  */
		if ((recvresp1 & recvresp2) == 0) {
			goto wait;
		}
  ... 
	}

 err_out:
  return 0;
}
