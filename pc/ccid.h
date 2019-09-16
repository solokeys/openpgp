/*
  Copyright 2019 SoloKeys Developers

  Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
  http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
  http://opensource.org/licenses/MIT>, at your option. This file may not be
  copied, modified, or distributed except according to those terms.
 */


#ifndef CCID_H_
#define CCID_H_

#include <stdint.h>

/* reg_callback.h */
typedef void (*ex_cb)(uint8_t*, size_t, uint8_t*, size_t*);

extern int usbip_ccid_start(ex_cb cb);



#endif /* CCID_H_ */
