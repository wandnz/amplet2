#ifndef _TESTS_UDPSTREAM_MOS_H
#define _TESTS_UDPSTREAM_MOS_H

/*
 * Recommended by section 7.7 of ITU-T G.107 (06/2015). This value was
 * previously set to 94.2
 */
#define DEFAULT_R_VALUE 93.2
#define IAN_MCDONALD_R_VALUE 94.2

/* default delay sensitivity class for normal users Table 1 ITU-T G.107 */
#define MINIMUM_PERCEIVABLE_DELAY 100.0
#define DELAY_SENSITIVITY 1.0

/* loss robustness factors from Table I.3/G.113 in ITU-T G.113 App I */
#define LOSS_ROBUSTNESS_G711 4.3
#define LOSS_ROBUSTNESS_G711_PLC 25.1
#define EQUIPMENT_IMPAIRMENT_G711 0.0

/* Value in microseconds where impact of delay increases */
#define IAN_MCDONALD_DELAY_THRESHOLD 177300

int calculate_icpif(uint32_t delay, double loss /* codec */);
int calculate_cisco_mos(int icpif);
double calculate_itu_rating(uint32_t delay, double loss,
        double avg_loss_length);
double calculate_itu_mos(double rating);

#endif
