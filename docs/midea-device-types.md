# Midea M-Smart device types — status field reference

Reference for extending `device/midea` beyond the air-conditioner codec. Gathered
from `wuwentao/midea_ac_lan` (`doc/<TYPE>.md`, attribute layer) and
`rokam/midea-local` (`midealocal/devices/<type>/`, the actual codecs).

- **Device-type code** = the 2 ASCII chars at `sn[8..10]` (serial = `SN8 + TT + UUUU`).
  `device::midea::device_type()` maps these.
- **Where the fields are**: attribute *names + enums* are in `doc/<TYPE>.md`; the
  **byte offsets** needed to parse a captured status frame are in
  `rokam/midea-local/midealocal/devices/<type>/message.py`. Build a codec by
  pairing the two.
- The transport + C1→C2→C3 handshake are appliance-agnostic — only the field
  codec below differs per type. `midea_ctl` already handshakes any type and logs
  the raw decrypted status frame for the ones without a codec.

`rokam/midea-local` ships codecs for **36 types**: a1 ac ad b0 b1 b3 b4 b6 b8 bf
c2 c3 ca cc cd ce cf da db dc e1 e2 e3 e6 e8 ea ec ed fa fb fc fd x13 x26 x34 x40.

## Types seen in our captures

| SN code | Appliance | Key status fields (read) | Controls (write) |
|---|---|---|---|
| **AC** | air-conditioner | run status, mode, set-temp, indoor/outdoor temp, fan | power, mode, temp, fan, swing *(codec done)* |
| **FC** | air-purifier | **pm25, tvoc, hcho, filter1/2 life** | power, mode (Auto/Manual/Sleep/Fast/Smoke), fan (Auto/Low/Med/High), anion, child_lock, standby, screen_display (Bright/Dim/Off), detect_mode (Off/PM2.5/Methanal) |
| **E2** | electric water heater | **current_temp, heating_power(W), heating, heat_insulating, protection** | power, target_temp, variable_heating, whole_tank_heating, sterilization, memory, auto_cut_out |
| **BF** | microwave/steam oven | **door (open/closed), current_temp, status, time_remaining, tank_ejected, water_shortage, water_change_reminder** | (none — read-only) |
| **B6** | range hood | **fan_level, cleaning_reminder, oilcup_full** | power, light, fan speed (Off/1/2/3/Variable) |
| **DB** | front-load washer | **status, mode, program, progress, time_remaining, water_level, temperature, dehydration speed/time, wash_time, detergent, softener, dirty_degree** | power, start |
| **E1** | dishwasher | **status, progress, time_remaining, temperature, humidity, error_code, door, rinse_aid (shortage), salt (shortage), softwater** | power, child_lock, storage, mode |

## Other common types

| SN code | Appliance | Key status fields | Controls |
|---|---|---|---|
| **A1** | dehumidifier | current_humidity, current_temperature, tank_full, filter_cleaning_reminder | power, mode (Manual/Continuous/Auto/Clothes-Dry/Shoes-Dry), fan_speed, target humidity, water_level_set (25/50/75/100), swing, anion, pump, child_lock |
| **FD** | humidifier | current_humidity, current_temperature | power, target humidity, mode, fan_speed (Lowest…High/Auto/Off), disinfect, screen_display |
| **FA** | fan | (speed level) | power, speed (N levels), oscillate, oscillation_mode (Off/Oscillation/Tilting/Curve-W/Curve-8/Both), oscillation_angle (30…360), tilting_angle, child_lock |
| **CE** | fresh-air | **co2, pm25, hcho, current_temp, current_humidity, filter_cleaning/change_reminder** | power, fan speed (1–7), aux_heating, eco_mode, sleep_mode, powerful_purify, link_to_ac, child_lock |
| **CD** | heat-pump water heater | top/bottom/compressor/condenser/outdoor/disinfection temps, compressor_status, water_level, elec_heat, eco, error_code | power, target_temp, mode, vacation_mode, vacation_days |
| **CA** | refrigerator | per-zone actual/setting temps (fridge/freezer/flex-zone), all door sensors + overtime, humidity, energy, variable_mode | (read-only) |

## Notes for building a codec

- **Booleans** (power, child_lock, anion, door, reminders) are the cheapest wins —
  single bits/bytes, unambiguous.
- **Enums** (mode, fan_speed, screen_display) map small integers to the labels
  above; exact integer↔label mapping is in each `message.py`.
- **Numerics** (pm25, temp, humidity, time_remaining) — watch scaling/units;
  `message.py` has the offset + any divisor. Temperatures are often integer °C or
  °C×2 (half-degree); don't guess — read the parser.
- Appliances with **no write service** (BF, CA) are monitor-only even with control
  support built — useful for a passive/status survey, not actuation.
- Our `midea_ctl` already logs `midea[SN] status (<type>, no codec): <hex>` for
  every non-AC type — capture those next to the Midea app and diff against the
  `message.py` offsets to implement a type's `Status` parser.
