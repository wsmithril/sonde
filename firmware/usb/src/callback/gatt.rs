//! GATT-enum mode setup callback (usb). The `setup` future handed to the mode maps
//! the QSPI asset window (so UUIDs resolve to names) and spawns the state-colour LED;
//! the mode `await`s it inside `init`, then drives the enumerator.

use embassy_executor::Spawner;

use sonde_common::mode::{self, Mode as _};
use sonde_common::{led, ulog};

use crate::{CTX, ConsoleSink, LedParts, QspiParts};

#[embassy_executor::task]
pub async fn run(spawner: Spawner, q: QspiParts, l: LedParts) {
    ulog!("mode=gatt_enum\r\n");
    let mut m = mode::GattEnum::<ConsoleSink>::new();
    m.init(&CTX, async move {
        crate::hold_assets(spawner, crate::qspi_setup(q));
        let pwm = led::Pwm::new(l.pwm, l.r, l.g, l.b);
        spawner.spawn(mode::gatt::led_task(pwm).unwrap());
    })
    .await;
    m.run(&CTX).await
}
