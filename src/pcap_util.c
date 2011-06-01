#include <pcap.h>

#include "pcap_util.h"
#include "debug.h"

pcap_t *pcap_init(char *iface, int snaplen, int promisc, int rfmon, int cap_timeout)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = NULL;
  
  if (iface == NULL)
    fatal(__func__, "iface empty");
  
#ifdef HAVE_PCAP_CREATE

  pcap = pcap_create(iface, errbuf);
  
  if (pcap == NULL)
    fatal(__func__, errbuf);

  status = pcap_set_snaplen(pcap, snaplen);
  if (status != 0)
    fatal(__func__, "Can't set snapshot length on %s: %s", iface, pcap_statustostr(status));

  status = pcap_set_promisc(pcap, promisc);
  if (status != 0)
    warning("can't set promisc mode for %s: %s", iface, pcap_statustostr(status));

  status = pcap_set_rfmon(pcap, rfmon);
  if (status != 0)
    warning("can't set monitor mode for %s: %s", iface, pcap_statustostr(status));

  status = pcap_set_timeout(pcap, cap_timeout);
  if (status != 0)
    warning("can't set timeout: %s", pcap_statustostr(status));

  status = pcap_activate(pcap);
  switch(status) {
  case PCAP_ERROR:
    fatal(__func__, "%s", pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_NO_SUCH_DEVICE:
    fatal(__func__, "no such device (%s)", pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_PERM_DENIED:
    fatal(__func__, "permission denied (%s)", pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_IFACE_NOT_UP:
    fatal(__func__, "iface %s not up (%s)", iface, pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_RFMON_NOTSUP:
    fatal(__func__, "monitor mode not supported for %s (%s)", iface, pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_ACTIVATED:
    fatal(__func__, "%s", pcap_statustostr(status));
    break;
    
  case PCAP_WARNING:
    warning("%s", pcap_statustostr(status));
    break;
    
  case PCAP_WARNING_PROMISC_NOTSUP:
    warning("promisc mode for %s not supported (%s)", iface, pcap_statustostr(status));
    break;
  }
  
#else
  
  /* Open the device for capturing */
  pcap = pcap_open_live(iface, snaplen, promisc, cap_timeout, errbuf);

  if (pcap == NULL)
    fatal(__func__, errbuf);

#endif /* HAVE_PCAP_CREATE */
  
  return pcap;
}

void pcap_cleanup(pcap_t *pcap)
{
  if (pcap == NULL)
    return;
  
  pcap_close(pcap);
}
