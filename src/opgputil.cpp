// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include "opgputil.h"
#include "led.h"

void show_error() {
    led_rgb(0xFF0000U);
    while (true);
}

void std::__throw_out_of_range_fmt(char const*, ...) {show_error();};
