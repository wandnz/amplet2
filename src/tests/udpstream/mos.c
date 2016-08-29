/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <math.h>

#include "debug.h"
#include "mos.h"


/*
 * XXX All values currently for PCM G.711 codecs
 */
int calculate_icpif(uint32_t delay, double loss /* codec */) {
    /* Delay Impairment Factor */
    int idd = 0;
    /* Equipment Impairment Factor */
    int ie = 0;

    Log(LOG_DEBUG, "Calculating ICPIF");


    /* TODO delay should include codec delay, look ahead delay, DSP delay */
    /* TODO this should be a function rather than a look up table? */
    if ( delay < 50000 ) {
        idd = 0;
    } else if ( delay < 100000 ) {
        idd = 1;
    } else if ( delay < 150000 ) {
        idd = 2;
    } else if ( delay < 200000 ) {
        idd = 4;
    } else {
        idd = 7;
    }

    Log(LOG_DEBUG, "  Delay Impairment Factor: %d", idd);

    /* TODO this should be a function rather than a look up table? */
    if ( loss < 2.0 ) {
        ie = 0;
    } else if ( loss < 4.0 ) {
        ie = 12;
    } else if ( loss < 6.0 ) {
        ie = 22;
    } else if ( loss < 8.0 ) {
        ie = 28;
    } else {
        ie = 32;
    }

    Log(LOG_DEBUG, "  Equipment Impairment Factor: %d", ie);

    return idd + ie;
}



/*
 *
 */
int calculate_cisco_mos(int icpif) {
    int mos;

    Log(LOG_DEBUG, "Calculating Cisco MOS with ICPIF: %d", icpif);

    if ( icpif <= 3 ) {
        mos = 5;
    } else if ( icpif <= 13 ) {
        mos = 4;
    } else if ( icpif <= 23 ) {
        mos = 3;
    } else if ( icpif <= 33 ) {
        mos = 2;
    //} else if ( icpif <= 43 ) {
    } else {
        mos = 1;
    }

    return mos;
}


#if 0
double calculate_ian_mcdonald_rating(uint32_t delay, double loss) {
    double rating;
    double ie;
    double id;
    double l1, l2, l3;

    l1 = 0;
    l2 = 30;
    l3 = 15;

    /* Burstiness of loss doesn't appear to be taken into account here */
    ie = l1 + (l2 * log(1 + (l3 * loss)));

    Log(LOG_DEBUG, "Loss Impact: %f\n", ie);

    /*
     * Impact of delay doesn't appear to take into account jitter according
     * to the standard. I've added the maximum observed jitter to the delay
     * before calling this function to reflect the size of the jitter buffer
     * required and the delay that it adds. Impact increases beyond a certain
     * threshold.
     */
    delay = 205000;
    id = 0.024 * delay / 1000.0;
    if ( delay > IAN_MCDONALD_DELAY_THRESHOLD ) {
        id += 0.11 * ((delay - IAN_MCDONALD_DELAY_THRESHOLD) / 1000.0);
    }

    Log(LOG_DEBUG, "Delay Impact: %f\n", id);

    /*
     * R = Ro - Is - Id - Ie-eff + A
     * assuming default values, no echo, etc
     * R = Ro - Id - Ie
     */
    rating = IAN_MCDONALD_R_VALUE - ie - id;

    return rating;
}
#endif



/*
 *
 * Impact of delay doesn't appear to take into account jitter according
 * to the standard. I've added the maximum observed jitter to the delay
 * before calling this function to reflect the size of the jitter buffer
 * required and the delay that it adds. Impact increases beyond a certain
 * threshold.
 */
double calculate_itu_rating(uint32_t delay, double loss,
        double avg_loss_length) {
    double rating;

    double Ie;
    double Ieeff;
    double Ppl;
    double Bpl;
    double BurstR;

    double mT = MINIMUM_PERCEIVABLE_DELAY;
    double sT = DELAY_SENSITIVITY;
    double Ta = delay / 1000.0;
    double x;
    double Idd, part1, part2;

    Log(LOG_DEBUG, "Calculating ITU R value");

    /* calculate impact of loss on the rating */
    Ppl = loss;

    /* Values for G.711 from Appendix I of ITU-T G.113 */
    Ie = EQUIPMENT_IMPAIRMENT_G711;
    Bpl = LOSS_ROBUSTNESS_G711;

    /*
     * BurstR = average observed burst / expected burst for random loss
     * when packet loss is random BurstR = 1
     * when packet loss is bursty BurstR > 1
     */
    if ( avg_loss_length > 0 ) {
        /* assuming expected burst length is 1 during random loss */
        BurstR = avg_loss_length;
    } else {
        /* no loss, so assume packet loss is random */
        BurstR = 1;
    }

    /* formula 7-29 from ITU-T G.107 */
    Ieeff = Ie + (95 - Ie) * (Ppl / ((Ppl / BurstR) + Bpl));

    Log(LOG_DEBUG, "  Loss Impact: %f\n", Ieeff);

    /* ignore the effect of delay if it is under the minimum perceivable */
    if ( Ta <= mT ) {
        Idd = 0;
    } else {
        /* formula 7-27 and 7-28 from ITU-T G.107 */
        x = log(Ta / mT) / log(2);
        part1 = pow((1 + pow(x, 6 - sT)), 1 / (6 - sT));
        part2 = 3 * pow((1 + pow(x / 3, 6 - sT)), 1 / (6-sT));
        Idd = 25 * (part1 - part2 + 2);
    }

    Log(LOG_DEBUG, "  Delay Impact: %f\n", Idd);

    /*
     * R = Ro - Is - Id - Ie-eff + A
     * assuming default values, no echo, etc
     * R = Ro - Id - Ie
     */
    rating = DEFAULT_R_VALUE - Idd - Ieeff;

    Log(LOG_DEBUG, "R value: %.02f\n", rating);

    return rating;
}



/*
 * Converting the R-factor to a Mean Opinion Score is done using the formula
 * given in ITU-T G.107 (06/2015) "The E-model: a computational model for use
 * in transmission planning" Annex B.
 */
double calculate_itu_mos(double rating) {
    double mos;

    Log(LOG_DEBUG, "Calculating ITU MOS with R: %.02f", rating);

    if ( rating < 0 ) {
        mos = 1;
    } else if ( rating > 100 ) {
        mos = 4.5;
    } else {
        mos = 1 +
            (0.035 * rating) +
            (rating * (rating - 60) * (100 - rating) * 7 * 0.000001);
    }

    return mos;
}
