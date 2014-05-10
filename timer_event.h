#ifndef TIMER_EVENT_H
#define TIMER_EVENT_H

#include <time.h>

#include "context.h"

typedef struct timer_event
{
    int timer_id;               /**< the id of the  */
    void * arg;
    struct timeval sched_time;
} timer_event;

#endif
