#ifndef DDTRACE8_OBSERVERS_H
#define DDTRACE8_OBSERVERS_H

#include <Zend/zend_observer.h>

void ddtrace8_observer_rinit(void);
void ddtrace8_observer_rshutdown(void);

zend_observer_fcall ddtrace8_observer_fcall_init(zend_function *func);

#endif  // DDTRACE8_OBSERVERS_H
