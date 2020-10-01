#ifndef _MEASURED_W32_SERVICE_H
#define _MEASURED_W32_SERVICE_H

#define AMP_SERVICE_NAME "amplet2-client"

int actual_main(int argc, char *argv[]);
void service_main(DWORD argc, LPTSTR *argv);

#endif
